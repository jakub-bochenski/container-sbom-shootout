#!/bin/bash
set -euo pipefail

declare -A images=(
	[maven]=dependencytrack/apiserver:4.13.4
#	[gradle]=apache/kafka:3.9.1
  [gradle]=library/elasticsearch:8.17.10
	[go]=tykio/tyk-gateway:v5.8
	[nodejs]=library/ghost:6.0.5
	[python]=tensorflow/tensorflow:2.20.0-jupyter
)

if [[ ${1-} != "--summary" ]]
then
	rm -rf out
	mkdir -p out

	for lang in "${!images[@]}"
	do
		./shoot.bash "${images[$lang]}" > "out/out-${lang}.json"
	done
fi

for lang in "${!images[@]}"
do
	echo "=== Summary for $lang ==="
	./shoot.bash --summary < "out/out-${lang}.json"
done