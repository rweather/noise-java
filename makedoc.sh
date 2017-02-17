#!/bin/sh
rm -rf doc/html
mkdir -p doc/html
exec javadoc -sourcepath src/main/java/ \
    -subpackages com.southernstorm.noise.protocol \
    -d doc/html \
    -windowtitle "Noise-Java" \
    com.southernstorm.noise.protocol
