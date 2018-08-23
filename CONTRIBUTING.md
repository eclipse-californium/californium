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

## Legal Requirements

Californium is an [Eclipse IoT](https://iot.eclipse.org) project and as such is governed by the Eclipse Development process.
This process helps us in creating great open source software within a safe legal framework.

For you as a contributor, the following preliminary steps are required in order for us to be able to accept your contribution:

* Sign the [Eclipse Contributor Agreement](http://www.eclipse.org/legal/ECA.php).
    In order to do so:
  * Obtain an Eclipse Foundation user ID. Anyone who currently uses Eclipse Bugzilla or Gerrit systems already has one of those.
If you don't already have an account simply [register on the Eclipse web site](https://dev.eclipse.org/site_login/createaccount.php).
  * Once you have your account, log in to the [projects portal](https://projects.eclipse.org/), select *My Account* and then the *Eclipse ECA* tab.

* Add your GiHub username to your Eclipse Foundation account. Log in to Eclipse and go to [Edit my account](https://dev.eclipse.org/site_login/myaccount.php).

The easiest way to contribute code/patches/whatever is by creating a GitHub pull request (PR). When you do make sure that you *Sign-off* your commit records using the same email address used for your Eclipse account.

You do this by adding the `-s` flag when you make the commit(s), e.g.

    $> git commit -s -m "Shave the yak some more"

You can find all the details in the [Contributing via Git](http://wiki.eclipse.org/Development_Resources/Contributing_via_Git) document on the Eclipse web site.

## Making your Changes

1. Consider to start with creating an issue on GitHub to discuss your plans and get the proper startup information.
1. Ensure, your plans will work with java 1.7
1. Fork the repository on GitHub
1. Create a new branch for your changes based on the 2.0.x branch. 
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

