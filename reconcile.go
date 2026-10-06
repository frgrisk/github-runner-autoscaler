package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/go-github/v60/github"
	"golang.org/x/sync/errgroup"
)

// The webhook handler launches one runner per workflow_job "queued" delivery,
// and GitHub does not retry a delivery that fails or times out. On a schedule,
// reconcile lists the queued jobs of RECONCILE_REPOSITORIES and launches a
// runner for any job that has waited past stuckAfter without one. That covers
// lost deliveries, failed launches and instances that died before registering.

const (
	// stuckAfter is how long a queued job, and the newest runner launched for
	// it, get before the reconciler launches another. It must exceed the time
	// an instance takes to boot and take a job, or the reconciler duplicates
	// runners that are still starting.
	stuckAfter = 5 * time.Minute

	// maxLaunchesPerJob caps the instances started for one job, the webhook's
	// included. EC2 lists terminated instances for about an hour, so a job that
	// no runner ever takes costs at most this many instances an hour.
	maxLaunchesPerJob = 3

	pageSize = 100

	// listConcurrency bounds the job listings in flight, well under GitHub's
	// secondary rate limit on concurrent requests.
	listConcurrency = 8

	// queued is GitHub's workflow_job action, and run and job status, for
	// work waiting on a runner.
	queued = "queued"
)

func reconcile(ctx context.Context) error {
	repos := splitList(os.Getenv("RECONCILE_REPOSITORIES"))
	if len(repos) == 0 {
		return errors.New("RECONCILE_REPOSITORIES env var not set")
	}

	settings, err := loadLaunchSettings()
	if err != nil {
		return err
	}

	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(settings.defaultRegion))
	if err != nil {
		return err
	}

	pat, err := fetchPAT(ctx, cfg, settings.secretName)
	if err != nil {
		return err
	}

	gh := github.NewClient(nil).WithAuthToken(pat)
	ec2Clients := map[string]*ec2.Client{}

	var errs []error

	for _, repo := range repos {
		owner, name, ok := strings.Cut(repo, "/")
		if !ok {
			errs = append(errs, fmt.Errorf("repository %q is not owner/name", repo))

			continue
		}

		jobs, err := queuedJobs(ctx, gh, owner, name, time.Now())
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list queued jobs in %s: %w", repo, err))

			continue
		}

		for _, job := range jobs {
			region, _ := settings.placement(job.Labels)

			client, ok := ec2Clients[region]
			if !ok {
				regionCfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
				if err != nil {
					errs = append(errs, err)

					continue
				}

				client = ec2.NewFromConfig(regionCfg)
				ec2Clients[region] = client
			}

			err := reconcileJob(ctx, settings, client, job, time.Now())
			if err != nil {
				errs = append(errs, fmt.Errorf("job %d in %s: %w", job.GetID(), repo, err))
			}
		}
	}

	return errors.Join(errs...)
}

func reconcileJob(
	ctx context.Context,
	settings launchSettings,
	client ec2.DescribeInstancesAPIClient,
	job *github.WorkflowJob,
	now time.Time,
) error {
	if !slices.Contains(job.Labels, "ephemeral") {
		return nil
	}

	queuedFor := now.Sub(job.GetCreatedAt().Time)
	if queuedFor < stuckAfter {
		return nil
	}

	log := slog.With("jobID", job.GetID(), "job", job.GetName(), "labels", job.Labels)

	region, instanceTypes := settings.placement(job.Labels)

	unmatched := unmatchedLabels(job.Labels, settings.runnerLabels(region, instanceTypes[0]))
	if len(unmatched) > 0 {
		log.Warn("skipping job no runner from this stack can take", "unmatched", unmatched)

		return nil
	}

	launches, err := runnerLaunches(ctx, client, job.GetID())
	if err != nil {
		return err
	}

	needed, err := needsAnotherRunner(launches, now)
	if !needed {
		return err
	}

	log.Warn("queued job has no runner, launching one",
		"queuedFor", queuedFor.Round(time.Second), "launches", len(launches))

	_, err = launchRunner(ctx, settings, job.GetID(), job.Labels)

	return err
}

// needsAnotherRunner reports whether a job queued past stuckAfter should get
// another runner, given when runners were launched for it. Once the newest has
// had stuckAfter to start, a job that has used up maxLaunchesPerJob is
// reported as an error instead, so the invocation fails visibly.
func needsAnotherRunner(launches []time.Time, now time.Time) (bool, error) {
	for _, launched := range launches {
		if now.Sub(launched) < stuckAfter {
			return false, nil
		}
	}

	if len(launches) >= maxLaunchesPerJob {
		return false, fmt.Errorf("still queued after %d runner launches", len(launches))
	}

	return true, nil
}

// runnerLabels are the labels a runner launched in region on instanceType
// registers with. GitHub adds self-hosted, Linux and X64 itself; the rest must
// match config.sh --labels in user-data.sh. A label missing here makes the
// reconciler skip jobs the runner could take.
func (s launchSettings) runnerLabels(region string, instanceType types.InstanceType) []string {
	return append(
		[]string{"self-hosted", "linux", "x64", "ephemeral", region, string(instanceType)},
		s.extraLabels...,
	)
}

// unmatchedLabels returns the job labels the runner lacks. GitHub only assigns
// a job to a runner that has every one of its labels, compared without case.
func unmatchedLabels(jobLabels, runnerLabels []string) []string {
	var unmatched []string

	for _, label := range jobLabels {
		if !slices.ContainsFunc(runnerLabels, func(r string) bool {
			return strings.EqualFold(r, label)
		}) {
			unmatched = append(unmatched, label)
		}
	}

	return unmatched
}

// queuedJobs lists the jobs in owner/repo that are waiting for a runner and
// may have waited past stuckAfter. A run stays in_progress while some of its
// jobs still queue, so runs of both statuses are scanned.
func queuedJobs(
	ctx context.Context,
	gh *github.Client,
	owner, repo string,
	now time.Time,
) ([]*github.WorkflowJob, error) {
	var runIDs []int64

	// A run that starts between the two listings appears in both.
	seen := map[int64]bool{}

	for _, status := range []string{queued, "in_progress"} {
		opts := &github.ListWorkflowRunsOptions{
			Status:      status,
			ListOptions: github.ListOptions{PerPage: pageSize},
		}

		for {
			runs, resp, err := gh.Actions.ListRepositoryWorkflowRuns(ctx, owner, repo, opts)
			if err != nil {
				return nil, err
			}

			for _, run := range runs.WorkflowRuns {
				// A job cannot have queued longer than its run's latest
				// attempt has existed, so a younger run holds no stuck job.
				if seen[run.GetID()] || now.Sub(run.GetRunStartedAt().Time) < stuckAfter {
					continue
				}

				seen[run.GetID()] = true
				runIDs = append(runIDs, run.GetID())
			}

			if resp.NextPage == 0 {
				break
			}

			opts.Page = resp.NextPage
		}
	}

	perRun := make([][]*github.WorkflowJob, len(runIDs))

	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(listConcurrency)

	for i, runID := range runIDs {
		g.Go(func() error {
			jobs, err := queuedJobsInRun(gctx, gh, owner, repo, runID)
			perRun[i] = jobs

			return err
		})
	}

	err := g.Wait()
	if err != nil {
		return nil, err
	}

	return slices.Concat(perRun...), nil
}

func queuedJobsInRun(
	ctx context.Context,
	gh *github.Client,
	owner, repo string,
	runID int64,
) ([]*github.WorkflowJob, error) {
	var jobs []*github.WorkflowJob

	opts := &github.ListWorkflowJobsOptions{
		Filter:      "latest",
		ListOptions: github.ListOptions{PerPage: pageSize},
	}

	for {
		page, resp, err := gh.Actions.ListWorkflowJobs(ctx, owner, repo, runID, opts)
		if err != nil {
			return nil, err
		}

		for _, job := range page.Jobs {
			if job.GetStatus() == queued {
				jobs = append(jobs, job)
			}
		}

		if resp.NextPage == 0 {
			return jobs, nil
		}

		opts.Page = resp.NextPage
	}
}

// runnerLaunches returns the launch time of every instance tagged for jobID,
// whatever its state.
func runnerLaunches(
	ctx context.Context,
	client ec2.DescribeInstancesAPIClient,
	jobID int64,
) ([]time.Time, error) {
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{
		Filters: []types.Filter{{
			Name:   aws.String("tag:" + jobIDTagKey),
			Values: []string{strconv.FormatInt(jobID, 10)},
		}},
	})

	var launches []time.Time

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, reservation := range page.Reservations {
			for _, instance := range reservation.Instances {
				launches = append(launches, aws.ToTime(instance.LaunchTime))
			}
		}
	}

	return launches, nil
}
