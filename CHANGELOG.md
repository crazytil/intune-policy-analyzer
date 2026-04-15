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

### Fixed
- Rebuilt domain classification from scratch using Microsoft's official CSP area taxonomy instead of naive substring matching. Office, Device Guard, Core Isolation, firmware, and Outlook settings are now correctly classified into separate domains and will never be grouped together.
- Office ADMX settings are split by product (Word, Excel, Outlook, etc.) instead of lumped into a single "Office" bucket.
- Legacy device configuration properties use prefix-based matching against the actual property name rather than scanning display names for false-positive keywords.
