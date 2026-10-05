// Independent reference for src/geometry.ts: StampLayoutEngine.qrSidePx/byFractions and the QR's left edge (StampLayout.kt place()),
// transcribed literally into Java (Kotlin Float/Int arithmetic = Java float/int arithmetic, Math.round(float) included).
// Run: java scripts/QrSideTable.java > test/fixtures/geometry/qrside-java.json
public class QrSideTable {
    static final float QR_SIDE_FRACTION = 0.1525f, QR_MAX_WIDTH = 0.25f, MAX_PANEL_HEIGHT = 0.6f, PAD = 0.02f, MARGIN = 0.02f;
    static final int SEAL_SIDE_MODULES = 9 * 4 + 17 + 2 * 4, MIN_MODULE_PX = 3, QR_LONG_SIDE_DIVISOR = 8;
    static int byFractions(int w, int h) {
        int byWidth = Math.round(w * QR_SIDE_FRACTION);
        int lng = Math.max(w, h);
        if (lng <= QR_LONG_SIDE_DIVISOR * byWidth) return byWidth;
        int perModule = QR_LONG_SIDE_DIVISOR * SEAL_SIDE_MODULES;
        return (lng + perModule - 1) / perModule * SEAL_SIDE_MODULES;
    }
    static int qrSidePx(int w, int h) {
        return Math.max(0, Math.min(Math.min(Math.max(byFractions(w, h), SEAL_SIDE_MODULES * MIN_MODULE_PX), (int) (w * QR_MAX_WIDTH)),
            (int) (h * MAX_PANEL_HEIGHT - 2 * w * PAD)));
    }
    static int qrLeft(int w, int side) {   // FULL panel: panelLeft = margin, panelW = w - 2 * margin; left = floor(panelLeft + panelW - pad - qrSide)
        float margin = w * MARGIN, pad = w * PAD, panelW = w - 2 * margin, qrSide = side;
        return (int) Math.floor(margin + panelW - pad - qrSide);
    }
    public static void main(String[] a) {
        int[][] sizes = { {4000, 3000}, {3000, 4000}, {2448, 3264}, {3264, 2448}, {2000, 1500}, {1500, 1125}, {1600, 1200}, {1080, 1440}, {1440, 1080},
            {750, 563}, {1061, 1414}, {1414, 1061}, {4000, 1000}, {6000, 1500}, {4000, 400}, {600, 800}, {3024, 4032}, {4032, 3024}, {2304, 4096},
            {1836, 3264}, {2160, 3840}, {1200, 1600}, {1125, 1500}, {4000, 6000}, {1600, 2133}, {8000, 6000}, {6000, 8000}, {4080, 3060}, {3060, 4080},
            {1280, 960}, {960, 1280}, {1199, 1600}, {3001, 4000}, {2999, 4000}, {488, 3904}, {1200, 200}, {100, 100}, {1, 1}, {7999, 3}, {3, 7999} };
        StringBuilder sb = new StringBuilder("[\n");
        java.util.List<int[]> all = new java.util.ArrayList<>(java.util.Arrays.asList(sizes));
        for (int w = 300; w <= 6000; w += 137) for (int h = 300; h <= 6000; h += 211) all.add(new int[] { w, h });
        for (int i = 0; i < all.size(); i++) { int w = all.get(i)[0], h = all.get(i)[1], s = qrSidePx(w, h);
            sb.append(" [").append(w).append(", ").append(h).append(", ").append(s).append(", ").append(qrLeft(w, s)).append("]").append(i + 1 < all.size() ? ",\n" : "\n"); }
        System.out.print(sb.append("]\n"));
    }
}
