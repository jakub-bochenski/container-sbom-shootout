# SBOM Container Tools Shootout

Comparison of tools for generating CycloneDX SBOMs from container images.

Tools are evaluated based on the number of identified components and licenses. Only tools that generate valid CycloneDX
SBOMs are included in the analysis. Where possible, tools are run from Docker containers.

## Tools Compared

- [Syft](https://github.com/anchore/syft): CLI tool and library for generating a SBOM from
  container images and filesystems. Supports multiple formats and languages.
- [Trivy](https://github.com/aquasecurity/trivy): Security scanner that detects vulnerabilities, misconfigurations,
  secrets, and generates SBOMs for containers, Kubernetes, code repositories, and cloud environments.
- [Sbomgen](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html): Amazon Inspector SBOM Generator for
  producing SBOMs from archives, container images, directories, local systems, and compiled Go/Rust binaries. Scans for
  files containing package information.
- [Cdxgen](https://github.com/CycloneDX/cdxgen): Tool for creating CycloneDX SBOMs from source code and container
  images. Supports many languages and package managers.
- [Docker scout](https://github.com/docker/scout-cli): Docker's tool for analyzing images, dependencies, and
  vulnerabilities.
- [Tern](https://github.com/tern-tools/tern): Software composition analysis tool and Python library that generates SBOMs
  for container images and Dockerfiles, showing a layer-by-layer view of contents.

Execution details for each tool are at the top of the [shoot.bash](shoot.bash) file.

## Container Images Analyzed

- Maven: `dependencytrack/apiserver:4.13.4`
- Gradle: `library/elasticsearch:8.17.10`
- Go: `tykio/tyk-gateway:v5.8`
- Node: `library/ghost:6.0.5`
- Python: `tensorflow/tensorflow:2.20.0-jupyter`

# Results

Results are in the `out` folder. Re-run tests with `./sample.sh`.

To analyze a single image, use `./shoot.sh <image>`.

## Result Summary

![Result summary](results.png)

## Syft

- Syft identifies the most components and licenses of all tools.

## Trivy

- Trivy identifies slightly fewer components than Syft. It performs well for Python and Node license detection, but only
  finds a few licenses for Java or Go packages.

- Latest Trivy version (0.65.0) has a [bug](https://github.com/aquasecurity/trivy/issues/9300) causing it to generate
  invalid CycloneDX SBOMs. Version 0.64.1 was used for this comparison.

## Sbomgen

- Sbomgen is significantly faster than the other tools.

- Generates multiple entries for a single component, inflating the component count with duplicates.

- Treats Maven metadata files (pom.xml, pom.properties) as individual components. For example, for logback-classic it
  generates 5 components:

```
/opt/owasp/dependency-track/dependency-track-apiserver.jar/META-INF/maven/ch.qos.logback/logback-classic/pom.properties
/opt/owasp/dependency-track/dependency-track-apiserver.jar/META-INF/maven/ch.qos.logback/logback-classic/pom.xml
/opt/owasp/dependency-track/dependency-track-apiserver.jar/WEB-INF/lib/logback-classic-1.5.18.jar
/opt/owasp/dependency-track/dependency-track-apiserver.jar/WEB-INF/lib/logback-classic-1.5.18.jar/META-INF/maven/ch.qos.logback/logback-classic/pom.properties
/opt/owasp/dependency-track/dependency-track-apiserver.jar/WEB-INF/lib/logback-classic-1.5.18.jar/META-INF/maven/ch.qos.logback/logback-classic/pom.xml
```

- Generates invalid PURLs for some of the above entries, e.g. `pkg:maven/logback-classic@1.5.18`
- Lists multiple versions of the same component, even if only one is present:

```
ch.qos.logback:logback-classic  1.2.0
ch.qos.logback:logback-classic  1.2.13
ch.qos.logback:logback-classic  1.3.14
ch.qos.logback:logback-classic  1.5.18
ch.qos.logback:logback-classic  1.5.6
```

- Not open source
- Unclear how to report issues or request features (AWS support?)

## Cdxgen

- Generates many `file` components, which are not useful for license compliance or vulnerability detection.
- If you discount `file` components, cdxgen identifies the fewest components for Python and Go, and is second worst to
  Tern for Java and Node.
- Only identifies licenses for Node packages. Using `FETCH_LICENSE=true` or `--profile license-compliance` results in
  empty BOM.
- Docker image is [unable to scan images](https://github.com/CycloneDX/cdxgen/issues/2205); requires local installation
  and multiple dependencies.
- Least user-friendly tool (unusual argument parsing, explicit option needed for non-zero exit code on failure).

## Docker Scout

- Docker Scout does not generate a [valid CycloneDX SBOM](https://github.com/docker/scout-cli/issues/190).

## Tern

- Does not generate a valid CycloneDX SBOM.
- Takes about 10 times longer than other tools (e.g. ~20 minutes for the Python image).
- Docker image [does not build correctly](https://github.com/tern-tools/tern/issues/1256).
- Option to use `scancode`, but unable to [get it working](https://github.com/tern-tools/tern/issues/1258).
