.PHONY: release clean brunch shadow-cljs uberjar


release: clean brunch shadow-cljs uberjar

clean:
	-rm -r resources/links/manifest.json \
         resources/links/modules.edn \
         resources/public/links*.css \
         resources/public/links*.css.map \
         resources/public/links*.js \
         resources/public/links*.js.map

brunch:
	bin/brunch build --production

shadow-cljs:
	bin/shadow-cljs release browser

uberjar:
	false
