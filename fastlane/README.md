fastlane documentation
================
# Installation

Make sure you have the latest version of the Xcode command line tools installed:

```
xcode-select --install
```

Install _fastlane_ using
```
[sudo] gem install fastlane -NV
```
or alternatively using `brew install fastlane`

# Available Actions
### cibuild
```
fastlane cibuild
```

### test
```
fastlane test
```

### build_all
```
fastlane build_all
```

### static_code_analysis
```
fastlane static_code_analysis
```

### setup
```
fastlane setup
```
Setup dependencies and project


### generate_documentation
```
fastlane generate_documentation
```
Lane that (auto) genarates API documentation from inline comments.
### carthage_resolve_dependencies
```
fastlane carthage_resolve_dependencies
```
Lane that resolves the project dependencies using Carthage.

----

This README.md is auto-generated and will be re-generated every time [_fastlane_](https://fastlane.tools) is run.
More information about fastlane can be found on [fastlane.tools](https://fastlane.tools).
The documentation of fastlane can be found on [docs.fastlane.tools](https://docs.fastlane.tools).
