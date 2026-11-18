// Package conditionalaccess imports all conditional access detectors.
package conditionalaccess

import (
	_ "github.com/etcsec-com/permtracer/internal/audit/detectors/azure/conditional-access/controls"
	_ "github.com/etcsec-com/permtracer/internal/audit/detectors/azure/conditional-access/exclusions"
	_ "github.com/etcsec-com/permtracer/internal/audit/detectors/azure/conditional-access/policies"
)
