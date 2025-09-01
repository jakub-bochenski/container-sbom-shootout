#!/bin/bash
set -euo pipefail

: "${DOCKER_REGISTRY:=docker.io}"

main() {
	local -r image="$1"

	local sbomgen_cmd sbom_utility_cmd

	install-tools

	declare -A commands=(
		[syft]="
			docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
				-e SYFT_GOLANG_SEARCH_LOCAL_MOD_CACHE_LICENSES=true \
				-e SYFT_GOLANG_SEARCH_REMOTE_LICENSES=true \
				$DOCKER_REGISTRY/anchore/syft:v1.32.0 \
					-o cyclonedx-json \
					--select-catalogers -file \
					$image
		"
		[trivy]="
			docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
				$DOCKER_REGISTRY/aquasec/trivy:0.64.1 image \
					--scanners license \
					--license-full \
					--license-confidence-level 0 \
					--format cyclonedx \
					--skip-version-check \
					$image
		" # 0.65.0 see https://github.com/aquasecurity/trivy/issues/9300
		[cdxgen]="
			npx cdxgen \
				--fail-on-error \
				--output /dev/stdout \
				--type docker \
				--format cyclonedx-json \
				--install-deps true \
				$image
		" # `FETCH_LICENSE=true` or `--profile license-compliance` result in empty BOM
		[sbomgen]="
			$sbomgen_cmd container \
				--scan-sbom-output-format cyclonedx \
				--collect-licenses \
				--quiet \
				--image $image
		"
		[tern]="
			docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
				ternd:latest \
					--quiet \
					report \
					-f cyclonedxjson \
					-i $image
		" # `-x scancode` https://github.com/tern-tools/tern/issues/1258
		[scout]="
			docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
				$DOCKER_REGISTRY/docker/scout-cli:1.18 \
					sbom $image \
					--format cyclonedx
		"
	)

	echo "Generating SBOMs for image: $image" | info

	rm -rf sboms
	mkdir -p sboms

	local start_time end_time tool file

	results=$(mktemp)
	validation=$(mktemp)
	trap 'rm -f "$results" "$validation"' EXIT

	for tool in "${!commands[@]}"
	do
		file="sboms/$tool.cyclonedx.json"

		echo "Running $tool…" | info
		echo "${commands[$tool]}" | format-command

		start_time=$SECONDS
		eval "${commands[$tool]}" >"$file" 2> >(tool-output)
		end_time=$SECONDS

		if [ ! -f "$file" ]
		then
			echo "$tool: output not found: $file" | error
			continue
		fi

		if [ ! -s "$file" ]
		then
			echo "$tool: output is empty: $file" | error
			continue
		fi

		"$sbom_utility_cmd" validate -q -i "$file" >"$validation" || {
			echo "$tool: validation failed." | error
		}

		jq -n \
			--arg tool "$tool" \
			--arg time "$((end_time - start_time))" \
			--rawfile validation "$validation" \
			--rawfile sbom_raw "$file" \
			'
				{
					tool: $tool,
					time: ($time|tonumber),
					validation: $validation,
					sbom: $sbom_raw | fromjson
				}
			' >>"$results"
	done

	echo "Result summary:" | info
	cat "$results" | jq -s '.' | tee >(summary /dev/stdin)
}

install-tools() {
	sbom_utility_cmd=tools/sbom-utility

	local sbomgen_glob="tools/sbomgen/inspector-sbomgen-*/linux/amd64/inspector-sbomgen"
	sbomgen_cmd=$(compgen -G "$sbomgen_glob" || true)

	mkdir -p tools

	if ! command -v "$sbom_utility_cmd" >/dev/null 2>&1
	then
		echo "Installing sbom-utility…" | info
		{
			curl -sSL https://github.com/CycloneDX/sbom-utility/releases/download/v0.18.1/sbom-utility-v0.18.1-linux-amd64.tar.gz |
				tar -xz -C tools
			chmod +x "$sbom_utility_cmd"
		} 2> >(install-output)
	fi

	if ! command -v "$sbomgen_cmd" >/dev/null 2>&1
	then
		echo "Installing Amazon sbomgen…" | info
		{
			curl -sSL -o tools/sbomgen.zip https://amazon-inspector-sbomgen.s3.amazonaws.com/latest/linux/amd64/inspector-sbomgen.zip
			unzip -q -o tools/sbomgen.zip -d tools/sbomgen
			sbomgen_cmd=$(compgen -G "$sbomgen_glob")
			chmod +x "$sbomgen_cmd"
		} 2> >(install-output)
	fi

	if ! docker image inspect ternd:latest >/dev/null 2>&1
	then
		echo "Installing tern…" | info
		(
			cd tools
			git clone https://github.com/jakub-bochenski/tern.git # https://github.com/tern-tools/tern/issues/1256
			docker build -f tern/docker/Dockerfile -t ternd:latest tern
		) 2> >(install-output)
	fi

	if ! npx cdxgen --version >/dev/null 2>&1
	then
		echo "Installing cdxgen…" | info
		# https://github.com/CycloneDX/cdxgen/issues/2205
		npm install @cyclonedx/cdxgen 2>&1 | install-output
	fi
}

summary() {
	jq -r <"$1" '
    .[]
    | [
        .tool,
        .time,
        (.validation == "")
      ]
      + (
        .sbom.components
        | [
            .,
            map(select(.licenses != null)),
            map(select(.type == "library")),
            map(select(.type == "application")),
            map(select(.type == "framework")),
            map(select(.type == "file")),
            map(select(.type == "operating-system")),
            map(select(.type == "container")),
            map(select(.type == "device"))
          ]
        | map(length)
      ) as $counts
      | $counts,
        (
          ["", "", "", ""]
          + (
            $counts[4:]
            | map( . * 100 / $counts[3] | round | tostring + "%")
          )
        )
      | @tsv
  ' |
		column -t -s $'\t' -N 'tool,time (s),valid,total,licenses,library,application,framework,file,operating-system,container,device' |
		format-table
}

info() {
	date +%T | tr '\n' ' '
	tput setaf 4
	tput bold
	echo -n '[INFO] '
	tput sgr0
	cat -
} >&2

error() {
	date +%T | tr '\n' ' '
	tput setaf 1
	tput bold
	echo -n '[ERROR] '
	tput sgr0
	cat -
} >&2

tool-output() {
	tput setaf 6
	cat -
	tput sgr0
} >&2

install-output() {
	tput setaf 3
	cat -
	tput sgr0
} >&2

format-command() {
	tput bold
	cat - | tr $'\n\t' ' ' | tr -s ' '
	tput sgr0
	echo
} >&2

format-table() {
	local i=0 line
	while IFS= read -r line
	do
		if ((i++ == 0))
		then
			printf "%s\n" "$line"
		else
			if ((i / 2 % 2))
			then
				tput setab 236
				printf "%s" "$line"
				tput sgr0
			else
				printf "%s" "$line"
			fi
			echo
		fi
	done
} >&2

if [[ $1 == "--summary" ]]
then
	summary "${2-/dev/stdin}"
	exit $?
fi

main "$@"
