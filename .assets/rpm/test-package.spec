Name:           test-package
Version:        VERSION_PLACEHOLDER
Release:        1%{?dist}
Summary:        Test package for E2E native client testing
License:        MIT
URL:            https://github.com/artifact-keeper/test-package

Source0:        test-file.txt

BuildArch:      noarch

%description
A test package for E2E native client testing of the Artifact Keeper registry.

%install
mkdir -p %{buildroot}/opt/test-package
cp %{SOURCE0} %{buildroot}/opt/test-package/

%files
/opt/test-package/test-file.txt

%changelog
* Mon Jan 01 2024 Test Author <test@artifact-keeper.local> - 1.0.0-1
- Initial test package
