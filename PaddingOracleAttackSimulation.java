/**
 * Disclaimer: 
 * This code is for illustration purposes.
 * Do not use in real-world deployments.
 */

public class PaddingOracleAttackSimulation {

    private static class Sender {
        private byte[] secretKey;
        private String secretMessage = "Top secret!";

        public Sender(byte[] secretKey) {
            this.secretKey = secretKey;
        }

        // This will return both iv and ciphertext
        public byte[] encrypt() {
            return AESDemo.encrypt(secretKey, secretMessage);
        }
    }

    private static class Receiver {
        private byte[] secretKey;

        public Receiver(byte[] secretKey) {
            this.secretKey = secretKey;
        }

        // Padding Oracle (Notice the return type)
        public boolean isDecryptionSuccessful(byte[] ciphertext) {
            return AESDemo.decrypt(secretKey, ciphertext) != null;
        }
    }

    public static class Adversary {

        // This is where you are going to develop the attack
        // Assume you cannot access the key.
        // You shall not add any methods to the Receiver class.
        // You only have access to the receiver's "isDecryptionSuccessful" only.
        public String extractSecretMessage(Receiver receiver, byte[] ciphertext) {

            byte[] iv = AESDemo.extractIV(ciphertext);
            byte[] ciphertextBlocks = AESDemo.extractCiphertextBlocks(ciphertext);
            boolean result = receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(iv, ciphertextBlocks));
            System.out.println(result); // This is true initially, as the ciphertext was not altered in any way.

            // TODO: WRITE THE ATTACK HERE.
            byte[] ivCopy = new byte[iv.length]; //to keep the original iv
            for (int i=0; i<iv.length; i++){
                ivCopy[i] = iv[i];
            }

            int firstPaddingIndex=0;
            do { //find the start of padding
                if (ivCopy[firstPaddingIndex] == 0){
                    ivCopy[firstPaddingIndex] = 1;
                }
                else{
                    ivCopy[firstPaddingIndex] =0;
                }
                firstPaddingIndex++;
            }
            while (receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(ivCopy, ciphertextBlocks)));

            firstPaddingIndex--;
            int paddingNumber = iv.length - firstPaddingIndex; //number of paddings which is number of bytes and the number stored in them
            byte[] functionBlocks = new byte[ciphertextBlocks.length];

            for (int i=0; i<iv.length; i++){
                ivCopy[i] = iv[i];
            }

            for (int i=1; i<=paddingNumber; i++){ //initial known function bytes from the padding number we got
                functionBlocks[functionBlocks.length-i] = Byte.parseByte(String.valueOf(Byte.parseByte(String.valueOf(paddingNumber)) ^ iv[iv.length-i]));
            }

            byte[] letter = new byte[1];
            String message = "";

            while (paddingNumber < functionBlocks.length){ //until all bytes are known
                for (int i=1; i<=paddingNumber; i++){
                    ivCopy[ivCopy.length-i] = Byte.parseByte(String.valueOf(functionBlocks[functionBlocks.length-i] ^ (paddingNumber+1))); //the new iv with the new custom padding
                }
                for (int i=-128; i<128; i++){ //try all values to find which one
                    ivCopy[firstPaddingIndex-1] = Byte.parseByte(String.valueOf(i));
                    if (receiver.isDecryptionSuccessful(AESDemo.prepareCiphertext(ivCopy, ciphertextBlocks))){ //the correct guess
                        functionBlocks[functionBlocks.length-paddingNumber-1] = Byte.parseByte(String.valueOf(ivCopy[firstPaddingIndex-1] ^ (paddingNumber+1))); //the new known function byte
                        break;
                    }
                }
                letter[0] = Byte.parseByte(String.valueOf(functionBlocks[functionBlocks.length-paddingNumber-1] ^ iv[iv.length-paddingNumber-1]));
                message = new String(letter) + message;
                paddingNumber++;
                firstPaddingIndex--;
            }

            return message;
        }
    }

    public static void main(String[] args) {

        byte[] secretKey = AESDemo.keyGen();
        Sender sender = new Sender(secretKey);
        Receiver receiver = new Receiver(secretKey);

        // The adversary does not have the key
        Adversary adversary = new Adversary();

        // Now, let's get some valid encryption from the sender
        byte[] ciphertext = sender.encrypt();

        // The adversary  got the encrypted message from the network.
        // The adversary's goal is to extract the message without knowing the key.
        String message = adversary.extractSecretMessage(receiver, ciphertext);

        System.out.println("Extracted message = " + message);
    }
}