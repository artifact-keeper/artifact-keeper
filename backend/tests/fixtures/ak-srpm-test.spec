%global debug_package %{nil}
Name:           ak-srpm-test
Version:        1.0
Release:        1
Summary:        Artifact Keeper source package fixture
License:        MIT
BuildRequires:  make

%description
Fixture (#5278): a source package. Its header names the build host
architecture, provides every subpackage it builds and requires its
BuildRequires; repodata must still list it with arch src.

%package        sub
Summary:        Subpackage
%description    sub
Sub.

%package        app
Summary:        Needs ak-srpm-test-sub
Requires:       ak-srpm-test-sub = %{version}-%{release}
%description    app
App.

%files
%files sub
%files app
