fastlane documentation
----

# Installation

Make sure you have the latest version of the Xcode command line tools installed:

```sh
xcode-select --install
```

For _fastlane_ installation instructions, see [Installing _fastlane_](https://docs.fastlane.tools/#installing-fastlane)

# Available Actions

### cibuild

```sh
[bundle exec] fastlane cibuild
```



### test

```sh
[bundle exec] fastlane test
```



### build_all

```sh
[bundle exec] fastlane build_all
```



### static_code_analysis

```sh
[bundle exec] fastlane static_code_analysis
```



### setup

```sh
[bundle exec] fastlane setup
```

Setup dependencies and project



### generate_documentation

```sh
[bundle exec] fastlane generate_documentation
```

Lane that (auto) genarates API documentation from inline comments.

### carthage_resolve_dependencies

```sh
[bundle exec] fastlane carthage_resolve_dependencies
```

Lane that resolves the project dependencies using Carthage.

----

This README.md is auto-generated and will be re-generated every time [_fastlane_](https://fastlane.tools) is run.

More information about _fastlane_ can be found on [fastlane.tools](https://fastlane.tools).

The documentation of _fastlane_ can be found on [docs.fastlane.tools](https://docs.fastlane.tools).
