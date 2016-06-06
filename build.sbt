organization := "org.shu.zq"

name := "cert-demo"

version := "1.0"

scalaVersion := "2.11.8"

libraryDependencies ++= Seq(
  "org.bouncycastle" % "bcpg-jdk15on" % "1.54",
  "org.bouncycastle" % "bcpkix-jdk15on" % "1.54",

  "com.typesafe.scala-logging" % "scala-logging_2.11" % "3.1.0"
)
