package python

import "github.com/anchore/syft/syft/pkg"

func cpeFieldCandidates(name string) *pkg.CPEFieldCandidates {
	return &pkg.CPEFieldCandidates{
		Vendor:   []string{name, "python-" + name},
		TargetSW: []string{"python"},
	}
}
