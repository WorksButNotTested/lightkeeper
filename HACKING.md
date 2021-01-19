# Layout

* The Ghidra Module, Eclipse project and the `build.gradle` file is in the directory `lightkeeper` to prevent other files ending up in the release assets.
* The test_data contains coverage files in various formats

# Build from the command line

* See the [lightkeeper/build.gradle](lightkeeper/build.gradle) script
* Or the [GitHub build script](https://github.com/WorksButNotTested/lightkeeper/blob/9fdab0b90edc0dcc4df1194f0470be466b9da559/.github/workflows/build_on_tag_push.yml#L37-L40)

# Eclipse 
Assuming you've read `$GHIDRA_HOME/Extensions/Eclipse/GhidraDev/GhidraDev_README.html` and are familiar with Eclipse.

* Change the Ghidra Paths in the following files:
  * [lightkeeper/.classpath](lightkeeper/.classpath)
  * [lightkeeper/.project](lightkeeper/.classpath)
