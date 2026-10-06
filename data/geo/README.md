# Vietnam provinces (2025 administrative divisions)

`vn-provinces-2025.geojson` holds the boundaries of Vietnam's 34 province-level units.
It is administrative boundaries only: no photos and no user locations.

- Source: OpenStreetMap, relations tagged `boundary=administrative` + `admin_level=4` inside Vietnam,
  fetched through the Overpass API (overpass-api.de) on 2026-10-06.
- OSM relation ids: 1844412, 1873490, 1874283, 1875748, 1875866, 1875887, 1884018, 1884034, 1885367, 1887959, 1890793, 1891418, 1891483, 1895630, 1898458, 1898509, 1898590, 1898961, 1900963, 1901032, 1902682, 1902690, 1902930, 1902947, 1902967, 1903291, 1903322, 1903340, 1903400, 1903418, 1903516, 1904421, 1973756, 5522596.
- Processing: geometry simplified to about 200 m and coordinates rounded; each feature keeps only `name`, `name:en` and `relation_id`.
- Used by the CameraStamp Android app (com.essenty.camerastamp) to name the province for a photo's place stamp.

## Licence

Data © OpenStreetMap contributors, available under the Open Database Licence (ODbL) 1.0.
This file is a Derivative Database under ODbL, so it is published here under the same licence (share-alike).
See [LICENSE-ODbL.txt](LICENSE-ODbL.txt) and <https://www.openstreetmap.org/copyright>.
