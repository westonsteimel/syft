package rust

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/go-test/deep"
)

func TestParseCargoLock(t *testing.T) {
	expected := []pkg.Package{
		{
			Name:     "added-value",
			Version:  "0.14.2",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: nil,
		},
		{
			Name:     "alabaster",
			Version:  "0.7.12",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: nil,
		},
		{
			Name:     "appnope",
			Version:  "0.1.0",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: nil,
		},
		{
			Name:     "asciitree",
			Version:  "0.3.3",
			Language: pkg.Python,
			Type:     pkg.PythonPkg,
			Licenses: nil,
		},
	}

	fixture, err := os.Open("test-fixtures/cargo/Cargo.lock")
	if err != nil {
		t.Fatalf("failed to open fixture: %+v", err)
	}

	actual, err := parseCargoLock(fixture.Name(), fixture)
	if err != nil {
		t.Error(err)
	}

	differences := deep.Equal(expected, actual)
	if differences != nil {
		t.Errorf("returned package list differed from expectation: %+v", differences)
	}
}