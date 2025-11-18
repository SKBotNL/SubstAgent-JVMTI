import java.io.FileInputStream;
import java.io.IOException;
import java.util.Arrays;

// Test $SAME_LENGTH_ENV split in 3 byte arrays, the entirety of the read content overflows
class Test7 {
    static String correctFirstString = "Hi abcdefghijklmno A";
    static String correctSecondString = "ccording t";
    static String correctThirdString = "o all known laws of aviation, there is no way a bee should be able to fly";

    public static String toHexDump(String s) {
        byte[] bytes = s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            sb.append(String.format("%02X ", bytes[i] & 0xFF));
        }
        return sb.toString().trim();
    }

    @SuppressWarnings("CallToPrintStackTrace")
    public static void main(String[] args) throws IOException {
        try {
            FileInputStream fis = new FileInputStream("../data/test7.txt");
            byte[] firstBuf = new byte[20];
            int firstN = fis.read(firstBuf);
            byte[] firstContent = Arrays.copyOfRange(firstBuf, 0, firstN);
            String firstContentString = new String(firstContent);

            byte[] secondBuf = new byte[10];
            int secondN = fis.read(secondBuf);
            byte[] secondContent = Arrays.copyOfRange(secondBuf, 0, secondN);
            String secondContentString = new String(secondContent);

            byte[] thirdBuf = new byte[256];
            int thirdN = fis.read(thirdBuf);
            byte[] thirdContent = Arrays.copyOfRange(thirdBuf, 0, thirdN);
            String thirdContentString = new String(thirdContent);

            if (firstContentString.equals(correctFirstString) && secondContentString.equals(correctSecondString) && thirdContentString.equals(correctThirdString)) {
                System.err.println("Correct output");
                System.exit(0);
            } else {
                System.out.println("=== Incorrect output ===");
                System.out.printf("First content string was \"%s\", should be \"%s\"\n", firstContentString, correctFirstString);
                System.out.printf("First content string hex: \"%s\"\n", toHexDump(firstContentString));
                System.out.printf("Second content string was \"%s\", should be \"%s\"\n", secondContentString, correctSecondString);
                System.out.printf("Second content string hex: \"%s\"\n", toHexDump(secondContentString));
                System.out.printf("Third content string was \"%s\", should be \"%s\"\n", thirdContentString, correctThirdString);
                System.out.printf("Third content string hex: \"%s\"\n", toHexDump(thirdContentString));
                System.out.println("========================");
                System.exit(1);
            }
        } catch (IOException e) {
            throw e;
        }
    }
}