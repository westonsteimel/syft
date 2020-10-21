package python

import (
	"os"
	"testing"

	"github.com/go-test/deep"

	"github.com/anchore/syft/syft/pkg"
)

func assertPackagesEqual(t *testing.T, actual []pkg.Package, expected map[string]pkg.Package) {
	t.Helper()
	if len(actual) != len(expected) {
		for _, a := range actual {
			t.Log("   ", a)
		}
		t.Fatalf("unexpected package count: %d!=%d", len(actual), len(expected))
	}

	for _, a := range actual {
		expectedPkg, ok := expected[a.Name]
		if !ok {
			t.Errorf("unexpected package found: '%s'", a.Name)
		}

		for _, d := range deep.Equal(a, expectedPkg) {
			t.Errorf("diff: %+v", d)
		}

	}
}

func TestParseEggMetadata(t *testing.T) {
	tests := []struct {
		Fixture      string
		ExpectedPkgs map[string]pkg.Package
	}{
		{
			Fixture: "test-fixtures/egg-info/PKG-INFO",
			ExpectedPkgs: map[string]pkg.Package{
				"requests": {
					Name:         "requests",
					Version:      "2.22.0",
					Language:     pkg.Python,
					Type:         pkg.PythonPkg,
					Licenses:     []string{"Apache 2.0"},
					MetadataType: pkg.PythonEggWheelMetadataType,
					Metadata: pkg.EggWheelMetadata{
						Author:      "Kenneth Reitz",
						AuthorEmail: "me@kennethreitz.org",
					},
				},
			},
		},
		{
			Fixture: "test-fixtures/dist-info/METADATA",
			ExpectedPkgs: map[string]pkg.Package{
				"Pygments": {
					Name:         "Pygments",
					Version:      "2.6.1",
					Language:     pkg.Python,
					Type:         pkg.PythonPkg,
					Licenses:     []string{"BSD License"},
					MetadataType: pkg.PythonEggWheelMetadataType,
					Metadata: pkg.EggWheelMetadata{
						Author:      "Georg Brandl",
						AuthorEmail: "georg@python.org",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Fixture, func(t *testing.T) {
			fixture, err := os.Open(test.Fixture)
			if err != nil {
				t.Fatalf("failed to open fixture: %+v", err)
			}

			actual, err := parseWheelOrEggMetadata(fixture.Name(), fixture)
			if err != nil {
				t.Fatalf("failed to parse egg-info: %+v", err)
			}

			assertPackagesEqual(t, actual, test.ExpectedPkgs)
		})
	}

}
