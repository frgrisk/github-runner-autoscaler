package main

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/google/go-github/v60/github"
)

func TestNeedsAnotherRunner(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		launches []time.Time
		want     bool
		wantErr  bool
	}{
		{"webhook never launched one", nil, true, false},
		{"webhook runner went missing", []time.Time{now.Add(-6 * time.Minute)}, true, false},
		{
			"relaunch still starting",
			[]time.Time{now.Add(-12 * time.Minute), now.Add(-2 * time.Minute)},
			false,
			false,
		},
		{
			"launch limit reached",
			[]time.Time{
				now.Add(-30 * time.Minute),
				now.Add(-20 * time.Minute),
				now.Add(-10 * time.Minute),
			},
			false,
			true,
		},
		{
			"last launch still starting at the limit",
			[]time.Time{
				now.Add(-20 * time.Minute),
				now.Add(-10 * time.Minute),
				now.Add(-time.Minute),
			},
			false,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := needsAnotherRunner(tt.launches, now)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Errorf("needsAnotherRunner() = %v, %v; want %v, error %v",
					got, err, tt.want, tt.wantErr)
			}
		})
	}
}

//nolint:goconst // Cases spell out runs-on label lists literally.
func TestUnmatchedLabels(t *testing.T) {
	t.Parallel()

	settings := launchSettings{
		runnerConfig: map[string]RunnerConfiguration{
			"us-east-2": {},
			"eu-west-1": {},
		},
		defaultRegion: "us-east-2",
		extraLabels:   []string{"team-a"},
	}

	tests := []struct {
		name   string
		labels []string
		want   []string
	}{
		{
			"region and instance type labels",
			[]string{"self-hosted", "ephemeral", "team-a", "c8a.2xlarge", "us-east-2"},
			nil,
		},
		{
			"default region and instance type",
			[]string{"self-hosted", "Linux", "X64", "ephemeral", "team-a"},
			nil,
		},
		{
			"another stack's label",
			[]string{"self-hosted", "ephemeral", "team-b", "c8a.large"},
			[]string{"team-b"},
		},
		{
			"two instance types",
			[]string{"self-hosted", "ephemeral", "team-a", "c8a.large", "c7a.large"},
			[]string{"c7a.large"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			region, instanceTypes := settings.placement(tt.labels)

			got := unmatchedLabels(tt.labels, settings.runnerLabels(region, instanceTypes[0]))
			if !slices.Equal(got, tt.want) {
				t.Errorf("unmatchedLabels() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUserDataLabels(t *testing.T) {
	t.Parallel()

	settings := launchSettings{extraLabels: []string{"team-a", "gpu"}}

	script, err := settings.userData("pat", "us-east-2")
	if err != nil {
		t.Fatal(err)
	}

	want := `--labels "${INSTANCE_TYPE},ephemeral,X64,us-east-2,team-a,gpu"`
	if !strings.Contains(string(script), want) {
		t.Errorf("user data does not register runners with %s", want)
	}
}

func TestQueuedJobs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	started := map[int64]time.Time{
		1: now.Add(-20 * time.Minute),
		2: now.Add(-10 * time.Minute),
		3: now.Add(-time.Minute),
		4: now.Add(-15 * time.Minute),
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /repos/o/r/actions/runs", func(w http.ResponseWriter, r *http.Request) {
		runs := map[string]map[string][]int64{
			"queued":      {"": {1}},
			"in_progress": {"": {1, 3}, "2": {2, 4}},
		}[r.URL.Query().Get("status")]

		page := r.URL.Query().Get("page")
		if page == "" {
			setNextPage(w)
		}

		var body github.WorkflowRuns
		for _, id := range runs[page] {
			body.WorkflowRuns = append(body.WorkflowRuns, &github.WorkflowRun{
				ID:           &id,
				RunStartedAt: &github.Timestamp{Time: started[id]},
			})
		}

		writeJSON(t, w, body)
	})
	mux.HandleFunc(
		"GET /repos/o/r/actions/runs/{run}/jobs",
		func(w http.ResponseWriter, r *http.Request) {
			if got := r.URL.Query().Get("filter"); got != "latest" {
				t.Errorf("filter = %q, want latest", got)
			}

			switch r.PathValue("run") {
			case "3":
				t.Error("listed jobs of a run that started under stuckAfter ago")
			case "4":
				// Deleted after the runs were listed.
				w.WriteHeader(http.StatusNotFound)

				return
			}

			page := r.URL.Query().Get("page")
			if r.PathValue("run") == "1" && page == "" {
				setNextPage(w)
			}

			jobs := map[string]map[string][]*github.WorkflowJob{
				"1": {
					"": {{ID: new(int64(10)), Status: new("queued")}},
					"2": {
						{ID: new(int64(11)), Status: new("in_progress")},
						{ID: new(int64(12)), Status: new("queued")},
					},
				},
				"2": {"": {{ID: new(int64(20)), Status: new("queued")}}},
			}[r.PathValue("run")][page]

			writeJSON(t, w, github.Jobs{Jobs: jobs})
		},
	)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	gh := github.NewClient(nil)
	gh.BaseURL, _ = url.Parse(srv.URL + "/")

	jobs, err := queuedJobs(t.Context(), gh, "o", "r", now)
	if err == nil || !strings.Contains(err.Error(), "run 4") {
		t.Errorf("queuedJobs() error = %v, want run 4's listing failure", err)
	}

	ids := make([]int64, 0, len(jobs))
	for _, job := range jobs {
		ids = append(ids, job.GetID())
	}

	// Run 1 is listed under both statuses; its jobs must be reported once.
	if want := []int64{10, 12, 20}; !slices.Equal(ids, want) {
		t.Errorf("queued job IDs = %v, want %v", ids, want)
	}
}

func setNextPage(w http.ResponseWriter) {
	w.Header().Set("Link", `<https://api.github.com/x?page=2>; rel="next"`)
}

type fakeDescribeInstances struct {
	t     *testing.T
	pages []*ec2.DescribeInstancesOutput
}

func (f *fakeDescribeInstances) DescribeInstances(
	_ context.Context,
	in *ec2.DescribeInstancesInput,
	_ ...func(*ec2.Options),
) (*ec2.DescribeInstancesOutput, error) {
	want := []types.Filter{{
		Name:   new("tag:GitHub Workflow Job Event ID"),
		Values: []string{"42"},
	}}
	if !reflect.DeepEqual(in.Filters, want) {
		f.t.Errorf("filters = %+v, want %+v", in.Filters, want)
	}

	page := f.pages[0]
	f.pages = f.pages[1:]

	return page, nil
}

func TestRunnerLaunches(t *testing.T) {
	t.Parallel()

	first := time.Date(2026, 10, 6, 4, 0, 0, 0, time.UTC)
	second := first.Add(6 * time.Minute)

	client := &fakeDescribeInstances{t: t, pages: []*ec2.DescribeInstancesOutput{
		{
			Reservations: []types.Reservation{{Instances: []types.Instance{{LaunchTime: &first}}}},
			NextToken:    new("more"),
		},
		{
			Reservations: []types.Reservation{{Instances: []types.Instance{{LaunchTime: &second}}}},
		},
	}}

	launches, err := runnerLaunches(t.Context(), client, 42)
	if err != nil {
		t.Fatal(err)
	}

	if want := []time.Time{first, second}; !slices.Equal(launches, want) {
		t.Errorf("launches = %v, want %v", launches, want)
	}
}

func TestSplitList(t *testing.T) {
	t.Parallel()

	got := splitList(" octo-org/repo-a, ,octo-org/repo-b ")
	if want := []string{"octo-org/repo-a", "octo-org/repo-b"}; !slices.Equal(got, want) {
		t.Errorf("splitList() = %v, want %v", got, want)
	}
}

func writeJSON(t *testing.T, w http.ResponseWriter, v any) {
	t.Helper()

	err := json.MarshalWrite(w, v)
	if err != nil {
		t.Error(err)
	}
}
