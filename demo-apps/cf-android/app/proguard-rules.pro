# For more details, see http://developer.android.com/guide/developing/tools/proguard.html

# Californium should not need any R8 rules for it to work properly.


# The rules below are only added here for testing the sample app, you do not need to add them in your project.
# Keep line numbers for debugging
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
# Move all classes to the root package to see what happens with Californium
-repackageclasses ''
