import Dependencies._

ThisBuild / scalaVersion     := "3.2.1"
ThisBuild / version          := "0.1.0-SNAPSHOT"
ThisBuild / organization     := "com.example"
ThisBuild / organizationName := "example"

lazy val root = (project in file("."))
  .settings(
    name := "sample_issue_noc_aws",
    libraryDependencies ++= Seq(
      "org.bouncycastle" % "bcutil-jdk18on" % "1.72",
      "com.amazonaws" % "aws-java-sdk-acmpca" % "1.12.386"
    )
  )
