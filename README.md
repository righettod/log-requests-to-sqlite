[![Build Status](https://travis-ci.org/righettod/log-requests-to-sqlite.svg?branch=master)](https://travis-ci.org/righettod/log-requests-to-sqlite)
[![CircleCI](https://circleci.com/gh/righettod/log-requests-to-sqlite/tree/master.svg?style=svg)](https://circleci.com/gh/righettod/log-requests-to-sqlite/tree/master)
[![Coverity Status](https://scan.coverity.com/projects/17099/badge.svg)](https://scan.coverity.com/projects/righettod-log-requests-to-sqlite)
[![Known Vulnerabilities](https://snyk.io/test/github/righettod/log-requests-to-sqlite/badge.svg?targetFile=build.gradle)](https://snyk.io/test/github/righettod/log-requests-to-sqlite?targetFile=build.gradle)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![BAppStore Version](https://img.shields.io/badge/BApp%20Store-v1.0.5-orange.svg)](https://portswigger.net/bappstore/d916d94506734f3490e49391595d8747)

# Log Requests to SQLite

This extension has a single objective: 

*Keep a trace of every HTTP request that has been sent via BURP.*

Why?

When I perform an assessment of a web application, it is often spread on several days/weeks and during this assessment, I use the different tools proposed by BURP (Proxy, Repeater, Intruder, Spider, Scanner...) to send many HTTP request to the target application. 

Since a few months, I have met a situation that happens more and more with the time: Some time after the closure of the assessment (mission is finished and report has been delivered), the client ask this kind of question:
* Do you have evaluated this service or this URL?
* Is it you that have sent this "big request" to this service/URL on this date?
* How many requests do you have sent to the application or to this service?
* And so on...

Most of the time, I answer to the client in this way: "This is the IP used for the assessment (the IP is also in the report by the way), check the logs of your web server, web app server, WAF..." because it's up to the client to have the capacity to backtrack a stream from a specific IP address.

In the same time, I cannot give the BURP session file to the client because:
* I cannot ask to a client to buy a BURP licence just to see the session content.
* I cannot ask to a client to learn what is BURP and how to use BURP.
* Requests send via Intruder/Repeater/Spider/Scanner are not kept in the session log.

So, I have decided to write this extension in order to keep the information of any HTTP request sends in a SQLIte database that I can give to the client along the report and let him dig into the DB via SQL query to answer his questions and, in the same time, have a proof/history of all requests send to the target application...

Once loaded, the extension ask the user to choose the target database file (location and name) to use for the SQLite database or to continue using the current defined file in the previous session.

Regarding the file name to use, there no constraint applied on it but I recommend to use a file with the `.db` extension to facilitate the usage with a SQLite client for exploration operations.

After, the extension silently records every HTTP request send during the BURP session.

![Extension Log](example1.png)

![DB Content](example2.png)

# Options

## Scope

There is an option to restrict the logging to the requests that are included into the defined target scope (BURP tab **Target** > **Scope**):

![Scope Option Menu](example3.png)

## Images

There is an option to exclude the logging of the requests that target images (check is not case sensitive):

![Image Option Menu](example4.png)

The list of supported file extensions is [here](resources/settings.properties).

## Statistics

There is an option to obtain statistics about the information logged in the database:

![Image Stats Menu 1](example5a.png)

![Image Stats Menu 2](example5b.png)

# Build the extension JAR file

Use the following command and the JAR file will be located in folder **build/lib**:

```
$ gradlew clean fatJar
```

# Audit third party dependencies

The goal `dependencyCheckAnalyze` can be used to verify if one of the dependencies used contains CVE.

Use the command line option `-PodcGradlePluginVersion=x.x.x` to specify a specific version of the [OWASP Dependency Check Grable plugin](https://mvnrepository.com/artifact/org.owasp/dependency-check-gradle)

```
$ gradlew -PodcGradlePluginVersion=3.2.1 dependencyCheckAnalyze
```

# Night build

This [link](https://circleci.com/api/v1.1/project/github/righettod/log-requests-to-sqlite/latest/artifacts) provide the **url** where to download a night build of the extension JAR file:

```json
[ {
  "path" : "LogRequestsToSQLite-NightBuild.jar",
  "pretty_path" : "LogRequestsToSQLite-NightBuild.jar",
  "node_index" : 0,
  "url" : "https://11-144454154-gh.circle-artifacts.com/0/LogRequestsToSQLite-NightBuild.jar"
} ]
```

The attribute **url** must be used to download the JAR file.

# BApp Store

The extension is referenced [here](https://portswigger.net/bappstore/d916d94506734f3490e49391595d8747).

# Change log

**1.0.5**

* Add new stats and update display:
    * Add the size of the biggest request sent.
    * Add the maximal number of requests sent by second.
    * Review stats display to dynamically adapt data amount in KB, MB or GB.

**1.0.4**

* Fix the bug described in issue [#5](/../../issues/5).
* Add statistics about the DB content.
* Allow the user to select the DB location and file name.

**1.0.3**

* Fix the bug described in issue [#4](/../../issues/4).

**1.0.2**

* Add option to exclude image from logging.
* Prepare and finalize publishing of the extension to the BAppStore.

**1.0.1**

* Add the option to restrict the logging to the requests that are included into the defined target scope.

**1.0.0**

* Creation of the extension and initial release.

# SQLite client

Cross-platform: https://github.com/sqlitebrowser/sqlitebrowser
