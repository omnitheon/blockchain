
/* Blockchain.java
To execute the program:
  javac -cp "gson-2.8.2.jar" MiniProject[LETTER].java
  java -cp ".;gson-2.8.2.jar" MiniProject[LETTER] (Process Num)
Author: Adam Slowik and help/inspiration from the included sources.
Sources:
  Clark Elliot
  https://mkyong.com/java/how-to-parse-json-with-gson/
  http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
  https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
  https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
  https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
  https://www.mkyong.com/java/java-sha-hashing-example/
  https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
  https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
  https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.2/
-----------------------------------------------------------------------------------------------------*/
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.internal.LinkedTreeMap;
import java.io.*;
import java.net.*;
import java.util.*;
import java.security.*;
import java.security.spec.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.ReentrantLock;

class Block implements Serializable { // DONE
  static final long serialVersionUID = 2L;
  String blockID;
  String pHash;
  String data;
  String hash;
  String randomSeed;
  String UUID;
  String timestamp;
  String fName;
  String lName;
  String birthDay;
  String SSN;
  String condition;
  String remediation;
  String meds;
  int blockORIGIN;
  String verifyingProcess;

  public Block() {
  }

  public Block(String blockID, String pHash, String data, String randomSeed) {
    
    this.timestamp = Blockchain.getCurrentTime();
    this.blockID = blockID;
    this.pHash = pHash;
    setDataAttributes(data);
    this.randomSeed = randomSeed;
    if (this.blockID.equals("-1")){
      this.UUID = "00000000-0000-0000-0000-000000000000";
      this.hash = generateSHA256Hash(true);
    }
    else {
      this.UUID = java.util.UUID.randomUUID().toString();
      this.hash = generateSHA256Hash(false);
    }
    this.blockORIGIN = Blockchain.pnum;
  }

  public Block(LinkedTreeMap<String, Object> ltm) {
    this.UUID = (String) ltm.get("UUID");
    this.timestamp = (String) ltm.get("timestamp");
    this.blockID = (String) ltm.get("blockID");
    this.pHash = (String) ltm.get("pHash");
    setDataAttributes((String) ltm.get("data"));
    this.randomSeed = (String) ltm.get("randomSeed");
    this.hash = (String) ltm.get("hash");
    this.blockORIGIN = Blockchain.pnum;
  }

  private void setDataAttributes(String data) {
    this.data = data;
    String[] arr = data.split(" ");
    this.fName = arr[0];
    this.lName = arr[1];
    this.birthDay = arr[2];
    this.SSN = arr[3];
    this.condition = arr[4];
    this.remediation = arr[5];
    this.meds = arr[6];
  }

  private void randomizeRandomSeed() {
    Random rr = new Random();
    int rval = rr.nextInt(16777215);
    this.randomSeed = Integer.toString(rval);
  }

  private String generateSHA256Hash(boolean genesisHash) {
    String h = "";
    int i = 0;
    // System.out.println("[" + Blockchain.getProcString() + "] Starting work for
    // NEW block using seed " + this.randomSeed);
    do {
      try {
        if (i > 0) {
          this.randomizeRandomSeed();
          // System.out.println("\t[" + Blockchain.getProcString()+ "] Previous hash didnt
          // meet requirements...trying " + this.randomSeed);
          try {
            Thread.sleep(1000);
          } catch (Exception e) {
            e.printStackTrace();
          }
        }
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // "Three elements"
        md.update(this.randomSeed.getBytes());
        md.update(this.pHash.getBytes());
        md.update(this.data.getBytes());

        byte byteData[] = md.digest();
        StringBuffer sb = new StringBuffer();
        for (i = 0; i < byteData.length; i++) {
          sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
        }

        h = sb.toString();
        if (genesisHash)
          return h;
        i++;
      } catch (NoSuchAlgorithmException x) {
        x.printStackTrace();
      }
    } while (h.substring(0, 1).equals("a") || h.substring(0, 1).equals("b") || h.substring(0, 1).equals("c")
        || h.substring(0, 1).equals("d") || h.substring(0, 1).equals("e") || h.substring(0, 1).equals("f"));
    return h;
  }

  public void setBlockTimestamp(String t) {
    this.timestamp = t;
  }

  public void setBlockData(String data) {
    setDataAttributes(data);
  }

  public void setBlockID(String ID) {
    this.blockID = ID;
  }

  public void setVerifyingProcess(String procID){
    this.verifyingProcess = procID;
  }

  public void setBlockUUID() {
    this.UUID = java.util.UUID.randomUUID().toString();
    this.blockORIGIN = Blockchain.pnum;
  }

  public void setPrevBlockHash(String pHash) {
    this.pHash = pHash;
  }

  public void VERIFY_BLOCK() {
    this.hash = generateSHA256Hash(false);
  }

  public void setRandomSeed(String randomSeed) {
    this.randomSeed = randomSeed;
  }

  public int getBlockORIGIN() {
    return this.blockORIGIN;
  }

  public String getPatientFirstname() {
    return this.fName;
  }

  public String getBlockID() {
    return this.blockID;
  }

  public String getBlockHash() {
    return this.hash;
  }

  public String getBlockData() {
    return this.data;
  }

  public String getPrevBlockHash() {
    return this.pHash;
  }

  public String getRandomSeed() {
    return this.randomSeed;
  }

  public String getBlockTimestamp() {
    return this.timestamp;
  }

  public String getBlockUUID() {
    return this.UUID;
  }

  public String getBlockIDString() {
    return "BlockID: " + getBlockID();
  }

  public String getBlockHashString() {
    return "BlockHash: " + getBlockHash();
  }

  public String getBlockDataString() {
    return "BlockData: " + getBlockData();
  }

  public String getPrevBlockHashString() {
    return "PrevBlockHash: " + getPrevBlockHash();
  }

  public String getRandomSeedString() {
    return "RandomSeed: " + getRandomSeed();
  }

  public String getTimestampString() {
    return "Timestamp: " + getBlockTimestamp();
  }

  public String getUUIDString() {
    return "UUID: " + getBlockUUID();
  }

  public void showBlockContents() {
    System.out.println(getBlockIDString());
    System.out.println(getRandomSeedString());
    System.out.println(getPrevBlockHashString());
    System.out.println(getBlockHashString());
    System.out.println(getBlockDataString());
    System.out.println(getTimestampString());
    System.out.println(getUUIDString());
  }

}

class Key { // DONE
  String processNum;
  String publicKeyString;

  public Key(String processNum, String publicKeyString) {
    this.processNum = processNum;
    this.publicKeyString = publicKeyString;
  }

  public String toString() {
    return this.processNum + "," + this.publicKeyString;
  }
}

class BlockChainDatastructure implements Iterable<Block> { // DONE
  public ArrayList<Block> BC;
  public String lastBlockID;
  public String lastAddedHash = Blockchain.GENSIS_HASH;

  public BlockChainDatastructure() {
    this.BC = new ArrayList<Block>();
  }

  public BlockIterator iterator() {
    return new BlockIterator();
  }

  public boolean doesBlockUUIDExistAlready(Block b) {
    for (Block temp : this.BC) {
      if (temp.getBlockUUID().equals(b.getBlockUUID()))
        return true;
    }
    return false;
  }

  public void add(Block b) {
    b.setPrevBlockHash(this.lastAddedHash);
    this.lastBlockID = b.getBlockID();
    this.lastAddedHash = b.getBlockHash();
    this.BC.add(b);
  }

  public String getLastAddedBlockID(){
    return lastBlockID;
  }

  public int indexOf(Block b) {
    return this.BC.indexOf(b);
  }

  public int indexOf(String s) {
    System.out.println("\n\nString indexOf called...not implemented...\n\n");
    return 1;
  }

  public void remove(Block b) {
    this.BC.remove(b);
  }

  public void deleteAllBlocks() {
    BC.clear();
  }

  public int size() {
    return BC.size();
  }

  public Block get(int index) {
    return BC.get(index);
  }

  public String getGenesisUUID() {
    return BC.get(0).getBlockUUID();
  }

  public String getGenesisHash() { 
    return BC.get(0).getBlockHash();
  }

  class BlockIterator implements Iterator<Block> {
    int currentIndex = 0;

    @Override
    public boolean hasNext() {
      return currentIndex < BC.size();
    }

    @Override
    public Block next() {
      return BC.get(currentIndex++);
    }

    @Override
    public void remove() {
      BC.remove(--currentIndex);
    }
  }
}

class PublicKeyServer implements Runnable { // DONE
  public void run() {
    Socket keySock;
    System.out.println("[" + Blockchain.getProcString() + "] " + Blockchain.getCurrentTime()
        + " Starting Key Server input thread using " + Blockchain.publicKeyListenerPort);
    try {
      ServerSocket servsock = new ServerSocket(Blockchain.publicKeyListenerPort, 6);
      while (true) {
        keySock = servsock.accept();
        new PublicKeyWorker(keySock).start();
      }
    } catch (IOException ioe) {
      System.out.println(ioe);
    }
  }
}

class PublicKeyWorker extends Thread { // DONE
  Socket keySock;

  PublicKeyWorker(Socket s) {
    keySock = s;
  }

  @Override
  public void run() {
    if ((Blockchain.pnum == 1 || Blockchain.pnum == 0) && Blockchain.hasNOTSentPKEY) {
      Blockchain.hasNOTSentPKEY = false; // now it has..
      Multicast.KeySend(Blockchain.PKEYJSON);
    }
    try {
      Gson gson = new Gson();
      BufferedReader in = new BufferedReader(new InputStreamReader(keySock.getInputStream()));
      String data = in.readLine();
      Key publicKey = gson.fromJson(data, Key.class);
      Blockchain.publicKeyArray[Integer.parseInt(publicKey.processNum)] = publicKey;
      System.out.println("[" + Blockchain.getProcString() + "] PublicKeyWorker RECV " + Blockchain.getCurrentTime()
          + " - updating local datastructure...");
      keySock.close();
    } catch (IOException x) {
      x.printStackTrace();
    }
  }
}

class UnverifiedBlockServer implements Runnable {
  BlockingQueue<Block> queue;

  UnverifiedBlockServer(BlockingQueue<Block> queue) {
    this.queue = queue; // Constructor binds our prioirty queue to the local variable.
  }

  public static Comparator<Block> BlockTSComparator = new Comparator<Block>() {
    @Override
    public int compare(Block b1, Block b2) {
      String s1 = b1.getBlockTimestamp();
      String s2 = b2.getBlockTimestamp();
      if (s1.equals(s2)) {
        return 0;
      }
      if (s1 == null) {
        return -1;
      }
      if (s2 == null) {
        return 1;
      }
      return s1.compareTo(s2);
    }
  };

  public void run() { // Start up the Unverified Block Receiving Server
    Socket sock;
    System.out.println("[" + Blockchain.getProcString() + "] " + Blockchain.getCurrentTime()
        + " Starting the Unverified Block Server input thread using "
        + Integer.toString(Blockchain.unverifiedBlockListenerPort));
    try {
      ServerSocket UVBServer = new ServerSocket(Blockchain.unverifiedBlockListenerPort, 6);
      while (true) {
        sock = UVBServer.accept(); // Got a new unverified block
        new UnverifiedBlockWorker(sock).start(); // So start a thread to process it.
      }
    } catch (IOException ioe) {
      System.out.println(ioe);
    }
  }

  class UnverifiedBlockWorker extends Thread {
    Socket sock;

    UnverifiedBlockWorker(Socket s) {
      sock = s;
    }

    Block BR = new Block();

    public void run() {
      try {
        ObjectInputStream unverifiedIn = new ObjectInputStream(sock.getInputStream());
        BR = (Block) unverifiedIn.readObject(); // Read in the UVB as an object
        System.out.println(
            "[" + Blockchain.getProcString() + "] Received UVB: " + BR.getBlockTimestamp() + " " + BR.getBlockData());
        queue.put(BR);
        sock.close();
      } catch (Exception x) {
        x.printStackTrace();
      }
    }
  }

}

class UnverifiedBlockConsumer implements Runnable {
  PriorityBlockingQueue<Block> queue; // Passed from BC object.
  int PID;

  UnverifiedBlockConsumer(PriorityBlockingQueue<Block> queue) {
    this.queue = queue; // Constructor binds our prioirty queue to the local variable.

  }

  public void run() {
    String data;
    PrintStream toBlockChainServer;
    Socket BlockChainSock;
    String newblockchain;
    String fakeVerifiedBlock;
    Random r = new Random();

    System.out.println(
        "[" + Blockchain.getProcString() + "] Starting the Unverified Block Priority Queue Consumer thread.\n");
    String prevHash = Blockchain.BlockChain.getGenesisHash();
    Gson g = new GsonBuilder().create();
    Gson prettyG = new GsonBuilder().setPrettyPrinting().create();

    try {
      while (true) {
        Block b = queue.take();
        if (b == null)
          break;
        if (Blockchain.BlockChain.doesBlockUUIDExistAlready(b))
          continue;
        //b.setBlockUUID();
        b.setPrevBlockHash(Blockchain.BlockChain.lastAddedHash);
        b.setRandomSeed("12345");
        b.setVerifyingProcess(Integer.toString(Blockchain.pnum));
        b.VERIFY_BLOCK();
        Blockchain.SLEEP(1);
        b.setBlockID(Integer.toString(Integer.parseInt(Blockchain.BlockChain.getLastAddedBlockID())+1));
        if (Blockchain.BlockChain.doesBlockUUIDExistAlready(b))
          continue;
        Blockchain.BlockChain.add(b);
        String BLOCKCHAINJSON = g.toJson(Blockchain.BlockChain);
        Multicast.BlockChainSend(BLOCKCHAINJSON);
        String PRETTYBLOCKCHAINJSON = prettyG.toJson(Blockchain.BlockChain);
        System.out.println("[" + Blockchain.getProcString() + "] " + "Successfully verified BlockID#" + b.getBlockID()
            + " and added to chain...sending to consortium...chain size is " + Blockchain.BlockChain.size());
        Blockchain.SLEEP(1);
      }

    } catch (Exception e) {
      System.out.println(e);
    }
  }
}

class BlockchainServer implements Runnable { // DONE
  public void run() {
    int q_len = 6; /* Number of requests for OpSys to queue */
    Socket sock;
    System.out.println("[" + Blockchain.getProcString() + "] " + Blockchain.getCurrentTime()
        + " Starting Blockchain Server input thread using " + Blockchain.updatedBlockChainListenerPort);
    try {
      ServerSocket servsock = new ServerSocket(Blockchain.updatedBlockChainListenerPort, 6);
      while (true) {
        sock = servsock.accept();
        new BlockchainServerWorker(sock).start();
      }
    } catch (IOException ioe) {
      System.out.println(ioe);
    }
  }
}

class BlockchainServerWorker extends Thread { // DONE
  Socket sock;

  BlockchainServerWorker(Socket s) {
    sock = s;
  }

  public void run() {
    try {
      BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
      String originProc = in.readLine();
      String data = in.readLine();
      Gson g = new Gson();
      BlockChainDatastructure LT = g.fromJson(data, BlockChainDatastructure.class);
      BlockChainDatastructure bc = new BlockChainDatastructure();
      for (Block b : LT)
        bc.add(b);
      Gson gb = new GsonBuilder().create();
      String BLOCKCHAINJSON = gb.toJson(bc);
      System.out.println("[" + Blockchain.getProcString() + "] BlockchainServerWorker RECV from " 
                          + originProc + " " + Blockchain.getCurrentTime());
      sock.close();
      Blockchain.BlockChain = bc;
      if (Blockchain.pnum == 0)
        Blockchain.generateJSONString(Blockchain.BlockChain, "BlockchainLedger.json");
      
      Blockchain.SLEEP(1);
    } catch (IOException x) {
      x.printStackTrace();
    }
  }
}

class Multicast {
  private Multicast() {
  }

  public static void KeySend(String KEYJSON) {
    Socket sock;
    PrintStream toServer;
    int[] keyPorts = new int[] { 4710, 4711, 4712 };

    int i;
    System.out.println(
        "[" + Blockchain.getProcString() + "] SEND " + Blockchain.getCurrentTime() + " is sending public keys...");
    for (i = 0; i < keyPorts.length; i++) {
      try {
        sock = new Socket("localhost", keyPorts[i]);
        toServer = new PrintStream(sock.getOutputStream());
        toServer.println(KEYJSON);
        toServer.flush();
        sock.close();
      } catch (Exception x) {
        System.out.println("[" + Blockchain.getProcString() + "] Couldn't connect to port " + keyPorts[i]);
      }
    }

  }

  public static void BlockChainSend(String BLOCKCHAINJSON) {
    Socket sock;
    PrintStream toServer;
    int[] blockChainPorts = new int[] { 4930, 4931, 4932 };
    int i;
    System.out.println("[" + Blockchain.getProcString() + "] SEND " + Blockchain.getCurrentTime()
        + " is sending a new verified BlockChain...");
    for (i = 0; i < blockChainPorts.length; i++) {
      try {
        sock = new Socket("localhost", blockChainPorts[i]);
        toServer = new PrintStream(sock.getOutputStream());
        toServer.println(Blockchain.getProcString());
        toServer.println(BLOCKCHAINJSON);
        toServer.flush();
        sock.close();
      } catch (Exception x) {
        System.out.println("[" + Blockchain.getProcString() + "] Couldn't connect to port " + blockChainPorts[i]);
      }
    }

  }

  public static void UnverifiedSend(String blockData) {
    Socket UVBsock;
    String TimeStampString = Blockchain.getCurrentTime() + "." + Blockchain.getProcString();
    Random r = new Random();
    int[] unverifiedPorts = new int[] { 4820, 4821, 4822 };
    Block BR = new Block();
    BR.setBlockUUID();
    BR.setBlockData(blockData);
    BR.setBlockTimestamp(TimeStampString); // Will be able to priority sort by TimeStamp
    ObjectOutputStream toServerOOS = null; // Stream for sending Java objects
    for (int i = 0; i < Blockchain.numProcesses; i++) {// Send some sample Unverified Blocks (UVBs) to each process
      // System.out.println("[" + Blockchain.getProcString() + "] Sending
      // UVB#"+Integer.toString(BlockNum)+" to process " + i + "...");
      try {
        UVBsock = new Socket("localhost", unverifiedPorts[i]);
        toServerOOS = new ObjectOutputStream(UVBsock.getOutputStream());
        Thread.sleep((r.nextInt(9) * 100)); // Sleep up to a second to randominze when sent.
        toServerOOS.writeObject(BR); // Send the unverified block record object
        toServerOOS.flush();
        UVBsock.close();
      } catch (Exception x) {
        System.out.println("[" + Blockchain.getProcString() + "] Couldn't connect to port " + unverifiedPorts[i]);
      }

    }

  }
}

public class Blockchain {
  static private ReentrantLock mutex = new ReentrantLock();
  final static String GENSIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
  final static String HASHING_ALGORITHM = "RSA";
  static boolean hasNOTSentPKEY = true;
  static BlockChainDatastructure BlockChain = new BlockChainDatastructure();
  static String PKEYJSON;
  static int numProcesses = 3;
  static int pnum;
  static int publicKeyListenerPort;
  static int unverifiedBlockListenerPort;
  static int updatedBlockChainListenerPort;
  static Key[] publicKeyArray = new Key[3];
  public static Comparator<Block> BlockTSComparator = new Comparator<Block>() {
    @Override
    public int compare(Block b1, Block b2) {
      String s1 = b1.getBlockTimestamp();
      String s2 = b2.getBlockTimestamp();
      if (s1.equals(s2)) {
        return 0;
      }
      if (s1 == null) {
        return -1;
      }
      if (s2 == null) {
        return 1;
      }
      return s1.compareTo(s2);
    }
  };

  // This queue of UVBs must be concurrent because it is shared by producer
  // threads and the consumer thread
  final PriorityBlockingQueue<Block> ourPriorityQueue = new PriorityBlockingQueue<>(100, BlockTSComparator);

  public static String getProcString() {
    return "(P" + Blockchain.pnum + ")";
  }

  public static void SLEEP(long seconds) {
    System.out.println("\nSLEEPING for " + seconds + "\n");
    try {
      Thread.sleep(seconds * 1000);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static String getCurrentTime() {
    return String.format("%1$s%2$tF.%2$tT", "", new Date());
  }

  public static KeyPair generateKP(String algorithm) throws Exception {
    Random rr = new Random();
    int rval = rr.nextInt(16777215);
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
    SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rng.setSeed(rval);
    keyGenerator.initialize(1024, rng);
    return (keyGenerator.generateKeyPair());
  }

  public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
    Signature signer = Signature.getInstance("SHA1withRSA");
    signer.initSign(key);
    signer.update(data);
    return (signer.sign());
  }

  public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
    Signature signer = Signature.getInstance("SHA1withRSA");
    signer.initVerify(key);
    signer.update(data);
    return (signer.verify(sig));
  }

  public static byte[] convertToBytes(String s) {
    return Base64.getDecoder().decode(s);
  }

  public static byte[] getPublicKeyBytes(KeyPair KP) {
    return KP.getPublic().getEncoded();
  }

  public static String getPublicKeyString(KeyPair KP) {
    return Base64.getEncoder().encodeToString(Blockchain.getPublicKeyBytes(KP));
  }

  public static byte[] getPrivateKeyBytes(KeyPair KP) {
    return KP.getPrivate().getEncoded();
  }

  public static String getPrivateKeyString(KeyPair KP) {
    return Base64.getEncoder().encodeToString(Blockchain.getPrivateKeyBytes(KP));
  }

  public static void main(String argv[]) {
    Blockchain s = new Blockchain();
    s.run(argv);
  }

  public void run(String argv[]) {
    if (argv.length < 1)
      pnum = 0;
    else if (argv[0].equals("0"))
      pnum = 0;
    else if (argv[0].equals("1"))
      pnum = 1;
    else if (argv[0].equals("2"))
      pnum = 2;
    else
      pnum = 0;
    publicKeyListenerPort = 4710 + pnum;
    unverifiedBlockListenerPort = 4820 + pnum;
    updatedBlockChainListenerPort = 4930 + pnum;

    String publicKeyFileName = "publicKey.json";
    String blockChainFileName = "blockChain.json";

    try {
      KeyPair KP = generateKP(HASHING_ALGORITHM);
      String publicKey = Blockchain.getPublicKeyString(KP);
      String privateKey = Blockchain.getPrivateKeyString(KP);
      System.out.println("----------------------------------------");
      System.out.println("[" + Blockchain.getProcString() + "] Hello from process number: " + pnum);
      System.out.println("[" + Blockchain.getProcString() + "] Public Key Listener: " + publicKeyListenerPort);
      System.out
          .println("[" + Blockchain.getProcString() + "] Unverified Blocks Listener: " + unverifiedBlockListenerPort);
      System.out.println(
          "[" + Blockchain.getProcString() + "] Updated BlockChain Listener: " + updatedBlockChainListenerPort);
      System.out.println("[" + Blockchain.getProcString() + "] Public Key: " + publicKey);
      System.out.println("[" + Blockchain.getProcString() + "] Private Key: " + privateKey);
      System.out.println("----------------------------------------\n");
      Key PKEY = new Key(Integer.toString(pnum), publicKey);
      // Gson g = new GsonBuilder().setPrettyPrinting().create(); //For humans
      Gson g = new GsonBuilder().create();
      PKEYJSON = g.toJson(PKEY);

     

      new Thread(new PublicKeyServer()).start(); // New thread to process incoming public keys
      new Thread(new UnverifiedBlockServer(ourPriorityQueue)).start(); // New thread to process incoming unverified
      new Thread(new BlockchainServer()).start(); // New thread to process incoming public keys

      Blockchain.SLEEP(2);

      if (pnum == 2) {
        Blockchain.hasNOTSentPKEY = false; // now it has..
        Multicast.KeySend(PKEYJSON);
      }

      while (hasNOTSentPKEY) {
        System.out.println("Waiting for P2 to send public keys...");
        Blockchain.SLEEP(1);
      }

      Blockchain.SLEEP(5);

      String INPUT_FILE_CONVENTION = "BlockInput";
      String INPUT_FILE_EXTENSION = ".txt";
      ArrayList<String> dataInput = new ArrayList<String>();

      String blockInputFileName = INPUT_FILE_CONVENTION + Integer.toString(pnum) + INPUT_FILE_EXTENSION;
      System.out
          .println("[" + Blockchain.getProcString() + "] " + "Reading unverified data from " + blockInputFileName);
      ArrayList<String> temp = readInputFile(blockInputFileName);
      for (String s : temp)
        dataInput.add(s);

      System.out.println(
          "[" + Blockchain.getProcString() + "] 1 file ingested..." + dataInput.size() + " unverified blocks ready...");

      Blockchain.SLEEP(5);
      
      for (String s : dataInput){
        Multicast.UnverifiedSend(s); // Multicast some new unverified blocks out to all servers as data
        Blockchain.SLEEP(1);
      }
      Blockchain.SLEEP(5);

      // BUILDS GENESIS BLOCK
      System.out.println("[" + Blockchain.getProcString() + "] " + "Building the genesis block...");
      Block genesisRecord = Blockchain.generateGenesisBlock();
      String genesisSHA256Hash = genesisRecord.getBlockHash();
      byte[] genesisSHA256Bytes = genesisSHA256Hash.getBytes();
      Blockchain.BlockChain.add(genesisRecord);
      System.out.println("[" + Blockchain.getProcString() + "] "
          + "Building the block chain...ALL verified block hashes must NOT start with 'a', 'b', 'c', 'd', 'e', or 'f'.");

      Blockchain.SLEEP(5);
      new Thread(new UnverifiedBlockConsumer(ourPriorityQueue)).start();

    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static Block generateGenesisBlock() {
    return new Block("-1", GENSIS_HASH, "Genesis Block 9999.99.99 999-99-999 99999 999999 999999999", "12345");
  }

  public String generateJSONString(ArrayList<Block> a, String fileName) {
    Gson g = new GsonBuilder().setPrettyPrinting().create();
    writeJSONStringToDisk(g, a, fileName);
    return g.toJson(a);
  }

  public static String generateJSONString(BlockChainDatastructure a, String fileName) {
    try {
      mutex.lock();
      Gson g = new GsonBuilder().setPrettyPrinting().create();
      writeJSONStringToDisk(g, a, fileName);
      return g.toJson(a);
    } finally {
      mutex.unlock();
    }
  }

  public String generateJSONString(Key k, String fileName) {
    Gson g = new GsonBuilder().setPrettyPrinting().create();
    writeJSONStringToDisk(g, k, fileName);
    return g.toJson(k);
  }

  public String generateJSONString(KeyPair KP, String fileName) {
    Gson g = new GsonBuilder().setPrettyPrinting().create();
    writeJSONStringToDisk(g, KP, fileName);
    return g.toJson(KP);
  }

  public String generateJSONString(String s, String fileName) {
    Gson g = new GsonBuilder().setPrettyPrinting().create();
    writeJSONStringToDisk(g, s, fileName);
    return g.toJson(s);

  }

  public void writeJSONStringToDisk(Gson g, KeyPair KP, String fileName) {
    try (FileWriter writer = new FileWriter(fileName)) {
      g.toJson(KP, writer);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void writeJSONStringToDisk(Gson g, Key K, String fileName) {
    try (FileWriter writer = new FileWriter(fileName)) {
      g.toJson(K, writer);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public static void writeJSONStringToDisk(Gson g, BlockChainDatastructure a, String fileName) {
    try (FileWriter writer = new FileWriter(fileName)) {
      g.toJson(a, writer);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void writeJSONStringToDisk(Gson g, ArrayList<Block> a, String fileName) {
    try (FileWriter writer = new FileWriter(fileName)) {
      g.toJson(a, writer);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public void writeJSONStringToDisk(Gson g, String s, String fileName) {
    try (FileWriter writer = new FileWriter(fileName)) {
      g.toJson(s, writer);
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  public BlockChainDatastructure readJSONBlockChain(String fileName) {
    Gson g = new Gson();
    BlockChainDatastructure LT;
    BlockChainDatastructure BlockChain = new BlockChainDatastructure();
    try (Reader reader = new FileReader(fileName)) {
      LT = g.fromJson(reader, BlockChainDatastructure.class);
      for (Block b : LT)
        BlockChain.add(b);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return BlockChain;
  }

  public String readJSONString(String fileName) {
    Gson g = new Gson();
    String publicKey = "";
    try (Reader reader = new FileReader(fileName)) {
      publicKey = g.fromJson(reader, String.class);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return publicKey;
  }

  public Key readJSONPublicKeyString(String fileName) {
    Gson g = new Gson();
    Key publicKey = new Key("", "");
    try (Reader reader = new FileReader(fileName)) {
      publicKey = g.fromJson(reader, Key.class);
    } catch (IOException e) {
      e.printStackTrace();
    }
    return publicKey;
  }

  public ArrayList readInputFile(String fileName) {
    ArrayList AL = new ArrayList<String>();
    File f = new File(fileName);
    try {
      BufferedReader reader = new BufferedReader(new FileReader(f));
      String temp;
      try {
        while ((temp = reader.readLine()) != null)
          AL.add(temp);

      } catch (IOException io) {
        io.printStackTrace();
      }
    } catch (FileNotFoundException fnf) {
      fnf.printStackTrace();
    }
    return AL;
  }
}
