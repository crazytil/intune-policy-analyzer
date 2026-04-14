# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0.0] - 2026-04-15

### Added
- Added a Phase 4 optimisation engine that surfaces read-only consolidation candidates and fragmentation hotspots from the current Intune policy set.
- Added a dedicated Optimisation tab in the frontend with domain and platform filtering plus expanded recommendation details.
- Added regression coverage to prevent optimisation findings from mixing incompatible policy families.

### Changed
- Tightened optimisation clustering so recommendations stay within the same policy family, platform, audience, and domain.
- Updated the README to reflect the current sign-in flow and the actual V1 optimisation scope.
