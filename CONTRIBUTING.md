# How to contribute to Eclipse Californium

First of all, thanks for considering to contribute to Eclipse Californium. We really appreciate the time and effort you want to spend helping to improve things around here. And help we can use :-)

Here is a (non-exclusive, non-prioritized) list of things you might be able to help us with:

* bug reports
* bug fixes
* improvements regarding code quality e.g. improving readability, performance, modularity etc.
* documentation (Getting Started guide, Examples etc)
* features (both ideas and code are welcome)
* test cases

In order to get you started as fast as possible we need to go through some organizational issues first, though.

## Eclipse Contributor Agreement

Before your contribution can be accepted by the project team contributors must
electronically sign the Eclipse Contributor Agreement (ECA).

* http://www.eclipse.org/legal/ECA.php

Commits that are provided by non-committers must have a Signed-off-by field in
the footer indicating that the author is aware of the terms by which the
contribution has been provided to the project. The non-committer must
additionally have an Eclipse Foundation account and must have a signed Eclipse
Contributor Agreement (ECA) on file.

For more information, please see the Eclipse Committer Handbook:
https://www.eclipse.org/projects/handbook/#resources-commit

## Making your Changes

1. Consider to start with creating an issue on GitHub to discuss your plans and get the proper startup information.
1. Ensure, your plans will work with java 1.7
1. Fork the repository on GitHub
1. Create a new branch for your changes based on the master branch.
   Please note: work based on other branches without prior discussion in an issue, may be in vain.
1. If you use the eclipse IDE, please import our prefer formatter `eclipse-formatter-profile.xml` from the californium parent-folder and apply it to your changes (only :-) ).
1. Make your changes 
1. Make sure you include test cases for non-trivial features/changes
1. Make sure the test suite runs successfully after you made your changes
1. If new files are created, provide a proper license header
   (see license_header_template.txt and copy the adjusted javadoc comment to the top of your java file)
1. Commit your changes into the branch you created in step 2
1. Use descriptive and meaningful commit messages
1. If you have a lot of commits squash them into a single commit
1. Make sure you use the `-s` flag when committing as explained above
1. Push your changes to your branch in your forked repository

## Submitting the Changes

Submit a pull request via the normal GitHub UI.

## After Submitting

* Do not use your branch for any other development, otherwise further changes that you make will be visible in the PR.

