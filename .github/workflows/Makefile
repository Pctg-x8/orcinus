.PHONY: all

all: test_example.yml publish.yml

test_example.yml: test_example.dhall
	dhall-to-yaml --file test_example.dhall --output test_example.yml

publish.yml: publish.dhall
	dhall-to-yaml --file publish.dhall --output publish.yml
