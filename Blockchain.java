
/*-----------------------------------------------------------------------------------------------------
1. Name / Date: Adam Slowik / 11/4/20
2. Java version used, if not the official version for the class: Not 100% sure, but here is my output:
    java version "14.0.2" 2020-07-14, Java(TM) SE Runtime Environment (build 14.0.2+12-46).
3. Precise command-line compilation examples / instructions:
    Navigate to working directory of Blockchain.java and execute 'javac -cp "gson-2.8.2.jar" *.java' two times.
    
4. Precise examples / instructions to run this program:
    General program usage syntax is as follows: 'java -cp ".;gson-2.8.2.jar" Blockchain [pNum]', where pNum is Process number. 
    There are 3 required processes to start this program, 0, 1 and 2.
      In different terminal prompts, execute the following commands in quick succession:
          java -cp ".;gson-2.8.2.jar" Blockchain 0
          java -cp ".;gson-2.8.2.jar" Blockchain 1
          java -cp ".;gson-2.8.2.jar" Blockchain 2
      Once process 2 initializes, it will start the blockchain program.
5. List of files needed for running the program: I believe Blockchain.java is the only required file.
6. Notes: All processes run the same blockchain consortium, 3 are required in this implementation.
          Have tried my absolute best to make everything thread safe, and to handle all exceptions.
          Work algorithm is probably incorrect, I was slightly confused on what should be hashed, when it should be hashed after being added, etc.
          Lots of hacky design decisions to get this to somewhat of a finished project, my apologies.
          The program does not create 'BlockchainLog.txt' due to some slight confusion in the functional requirements. Please see D2L discussion board, as I posted about this.
            I manually created this log file via redirects into files (i.e. java -cp ".;gson-2.8.2.jar" Blockchain 0 >> BlockchainLog.txt)

Sources:
  Clark Elliot
  JAVA API DOCS
  GeeksforGeeks as a general API reference
  https://mkyong.com/java/how-to-parse-json-with-gson/
  http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
  https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
  https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
  https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
  https://www.mkyong.com/java/java-sha-hashing-example/
  https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
  https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html
  http://www.fredosaurus.com/notes-java/data/strings/96string_examples/example_stringToArray.html
  https://beginnersbook.com/2013/12/linkedlist-in-java-with-example/
  https://www.javacodegeeks.com/2013/07/java-priority-queue-priorityqueue-example.html
  http://tutorials.jenkov.com/java-util-concurrent/blockingqueue.html
  http://tutorials.jenkov.com/java-util-concurrent/priorityblockingqueue.html
  https://andersbrownworth.com/blockchain/
  https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.2/
  https://www.baeldung.com/java-RL
  https://www.quickprogrammingtips.com/java/how-to-generate-sha256-hash-in-java.html  @author JJ
  https://dzone.com/articles/generate-random-alpha-numeric
  http://www.javacodex.com/Concurrency/PriorityBlockingQueue-Example
-----------------------------------------------------------------------------------------------------*/
import com.google.gson.Gson; //GSON libraries for formatting object and program data as JSON strings.
import com.google.gson.GsonBuilder;
import java.io.*; // InputOutput Java libs
import java.net.*; // Network Java libs
import java.util.*; // InputOutput Java libs
import java.security.*; // Various security/crpto framework Java libs
import java.util.concurrent.*; // Concurrency/Thread-handling Java libs
import java.util.concurrent.locks.ReentrantLock; // For making Blockchain.json

import javax.lang.model.element.QualifiedNameable;

class Block implements Serializable { // Block object to store and track state of blocks
  static final long serialVersionUID = 2L; //UID to allow Block to be Serializable. Arbitrary.
  String blockID; //ID in the chain, this is the index position.
  String pHash; //Previous block hash
  String data; //Raw block data
  String hash; //Computed hash
  String randomSeed; //Nonce for mining
  String UUID; //UUID for the block, only one can exist to ensure a non-duplicated BC.
  String timestamp; //Timestamp of when the block was created
  
  //Instance vars for the patient data, helpful during initial design phase.
  String fName;
  String lName;
  String birthDay;
  String SSN;
  String condition;
  String remediation;
  String meds;

  int blockORIGIN; //What process created this block?
  String verifyingProcess; //What process verified this block?

  public Block() {  } //non-param constructor

  public Block(String blockID, String pHash, String data, String randomSeed) { //general constructor

    this.timestamp = Blockchain.getCurrentTime(); //Need to get time a lot, why not make it a function?
    this.blockID = blockID;
    this.pHash = pHash;
    setDataAttributes(data); //Parse the raw data for various space-delimited attributes
    this.randomSeed = randomSeed;
    if (this.blockID.equals("-1")) { //The genesis or, "dummy" block has an ID of -1
      this.UUID = "00000000-0000-0000-0000-000000000000";
      this.hash = generateSHA256Hash(true); //I dont want to "work" on this hash, pass true
    } else {
      this.UUID = java.util.UUID.randomUUID().toString(); //If not genesis, randomly generate.
      this.hash = generateSHA256Hash(false); // Not genesis, pass false
    }
    this.blockORIGIN = Blockchain.pNum; //Constructor implies creation, capture originating process.
  }

  private void setDataAttributes(String data) { //helper function to parse raw data.
    this.data = data;
    String[] arr = data.split(" "); //staticly index into space-delimited values;
    this.fName = arr[0];
    this.lName = arr[1];
    this.birthDay = arr[2];
    this.SSN = arr[3];
    this.condition = arr[4];
    this.remediation = arr[5];
    this.meds = arr[6];
  }

  private void randomizeRandomSeed() { //If the first see wasnt random enough, re-randomize!
    Random rr = new Random();
    int rval = rr.nextInt(16777777);
    this.randomSeed = Integer.toString(rval);
  }

  private String generateSHA256Hash(boolean genesisHash) {//AKA, the "Work" algorithm
    String h = "";
    int i = 0; //Number of attempts to mine winning hash
    System.out.println("[" + Blockchain.getProcString() + "] Starting work for NEW block using seed " + this.randomSeed);
    do {
      try {
        if (i > 0) {
          this.randomizeRandomSeed(); //If the hashing doesnt produce a favorable hash, re-randomize the Nonce.
          System.out.println("\t[" + Blockchain.getProcString()+ "] Previous hash didnt meet requirements...trying " + this.randomSeed);
          Blockchain.SLEEP(1); //Sleep to introduce extra 'fake' work;
        }
        MessageDigest SHAMDigest = MessageDigest.getInstance("SHA-256"); //Generates the SHA-256 hash after appending bytes.

        // "Three elements" that make up a potential wishing hash.
        SHAMDigest.update(this.randomSeed.getBytes());
        SHAMDigest.update(this.pHash.getBytes());
        SHAMDigest.update(this.data.getBytes());

        byte byteDataArray[] = SHAMDigest.digest(); //digest the hash as bytes.
        StringBuffer sbuffer = new StringBuffer(); //Converts the digest bytes to ASCII chars
        for (i = 0; i < byteDataArray.length; i++) 
          sbuffer.append(Integer.toString((byteDataArray[i] & 0xff) + 0x100, 16).substring(1));
        h = sbuffer.toString();
        if (genesisHash) //No work for genesis hash
          return h;
        i++; //Increment tries, this doesnt matter if the do while ends.
      } catch (NoSuchAlgorithmException x) {
        x.printStackTrace();
      }// To enable 'work', force hashes to produce a hash that starts with an integer.
    } while (h.substring(0, 1).equals("a") || h.substring(0, 1).equals("b") || h.substring(0, 1).equals("c")
        || h.substring(0, 1).equals("d") || h.substring(0, 1).equals("e") || h.substring(0, 1).equals("f"));
    return h;
  }


  //General Setters for Block
  public void setBlockTimestamp(String t) { this.timestamp = t; }
  public void setPrevBlockHash(String pHash) { this.pHash = pHash; }
  public void setRandomSeed(String randomSeed) { this.randomSeed = randomSeed; }
  public void setBlockData(String data) { setDataAttributes(data); }
  public void setBlockID(String ID) { this.blockID = ID; }
  public void setVerifyingProcess(String procID) { this.verifyingProcess = procID; }
  public void setBlockUUID() {
    this.UUID = java.util.UUID.randomUUID().toString();
    this.blockORIGIN = Blockchain.pNum;
  }

  //Special Setter, used to commence work during consumer queue.
  public void VERIFY_BLOCK() { this.hash = generateSHA256Hash(false); }

  //General Getters for Block
  public int getBlockORIGIN() { return this.blockORIGIN; }
  public String getPatientFirstname() { return this.fName;  }
  public String getBlockID() { return this.blockID; }
  public String getBlockHash() { return this.hash; }
  public String getBlockData() { return this.data; }
  public String getPrevBlockHash() { return this.pHash; }
  public String getRandomSeed() { return this.randomSeed; }
  public String getBlockTimestamp() { return this.timestamp; }
  public String getBlockUUID() { return this.UUID; }
}

class Key { // Key class, helpful for marshalling over public keys for each process
  String processNum;
  String publicKeyString;

  public Key(String processNum, String publicKeyString) { 
    this.processNum = processNum;
    this.publicKeyString = publicKeyString;
  }
  public String toString() { return this.processNum + "," + this.publicKeyString; } //CSV
}

class BlockChainDS implements Iterable<Block> { // Blockchain construct, stores all the blocks.
  public ArrayList<Block> BC; //enabled by ArrayLists 
  public String lastBlockID; //The last blockID to be added to the chain
  public String lastAddedHash = Blockchain.GENSIS_HASH; //last hash to be added to the chain

  public BlockChainDS() { this.BC = new ArrayList<Block>(); } //Default constructor

  public BlockIterator iterator() { return new BlockIterator(); } //Iterator for Blocks

  public boolean doesBlockUUIDExistAlready(Block b) { //Helpful test in stopping block duplicates
    for (Block temp : this.BC) {
      if (temp.getBlockUUID().equals(b.getBlockUUID()))
        return true;
    }
    return false;
  }

  public void add(Block b) { //Add function to append new blocks to the chain
    b.setPrevBlockHash(this.lastAddedHash); //Use class variable to append PrevHash to block
    this.lastBlockID = b.getBlockID(); //Update class variables with newly last added block
    this.lastAddedHash = b.getBlockHash();
    this.BC.add(b); //Add to ArrayList.
  }

  public String getLastAddedBlockID() { return lastBlockID; } //Class variable getter
  public int indexOf(Block b) { return this.BC.indexOf(b); } //Hidden re-ruse of ArrayList method.
  public void remove(Block b) { this.BC.remove(b); } //Remove block from chain, if needed.
  public void deleteAllBlocks() { BC.clear(); } //Destroy the chain.
  public int size() { return BC.size(); } //How many blocks?
  public Block get(int index) { return BC.get(index); } //Get a specific block
  public String getGenesisUUID() { return BC.get(0).getBlockUUID(); } //Get genesis-block UUID
  public String getGenesisHash() { return BC.get(0).getBlockHash(); } //Get genesis-block Hash
  class BlockIterator implements Iterator<Block> { //Block iterator class for looping.
    int currentIndex = 0;

    @Override public boolean hasNext() { return currentIndex < BC.size(); }
    @Override public Block next() { return BC.get(currentIndex++); }
    @Override public void remove() { BC.remove(--currentIndex); } 
  }
}

//Public Key Handler - Server and Worker design
class PublicKeyServer implements Runnable { //Server
  public void run() {
    Socket clientKeySocket;
    System.out.println("[" + Blockchain.getProcString() + "] " + Blockchain.getCurrentTime()
        + " Starting Key Server input thread using " + Blockchain.publicKeyListenerPort);
    try {
      ServerSocket serverSocketVar = new ServerSocket(Blockchain.publicKeyListenerPort, 6); //Bind to socket
      while (true) {
        clientKeySocket = serverSocketVar.accept(); //Block wait til request.
        new PublicKeyWorker(clientKeySocket).start(); //Hand off client request to worker thread.
      }
    } catch (IOException ioe) { System.out.println(ioe); } }
}

class PublicKeyWorker extends Thread { // Worker for PublicKey Socket RECV
  Socket clientKeySocket;

  PublicKeyWorker(Socket s) { clientKeySocket = s; } //Socket from server thread

  @Override public void run() {
    if ((Blockchain.pNum == 1 || Blockchain.pNum == 0) && Blockchain.hasNOTSentPKEY) {
      //Hacky trick to pause P0 and P1 from executing. 
      Blockchain.hasNOTSentPKEY = false; // now it has..
      Multicast.KeySend(Blockchain.PKEYJSON);
    }
    try {
      Gson gson = new Gson(); //GSON for JSON
      BufferedReader in = new BufferedReader(new InputStreamReader(clientKeySocket.getInputStream()));
      String data = in.readLine(); //Read socket JSON input
      Key publicKey = gson.fromJson(data, Key.class); //Convert to helper key class for persistent storage.
      Blockchain.publicKeyArray[Integer.parseInt(publicKey.processNum)] = publicKey;
      System.out.println("[" + Blockchain.getProcString() + "] PublicKeyWorker RECV " + Blockchain.getCurrentTime()
          + " - updating local datastructure...");
      clientKeySocket.close();
    } catch (IOException x) { x.printStackTrace(); }
  }
}

//Unverified Block Handler
class UnverifiedBlockServer implements Runnable { //Server
  BlockingQueue<Block> Q; //Blocking queue from Main class thread

  // Constructor binds our prioirty queue to the local variable.
  UnverifiedBlockServer(BlockingQueue<Block> Q) { this.Q = Q; }

  @Override public void run() { // Start up the Unverified Block Receiving Server
    Socket socketVar;
    System.out.println("[" + Blockchain.getProcString() + "] " + Blockchain.getCurrentTime()
        + " Starting the Unverified Block Server input thread using "
        + Integer.toString(Blockchain.unverifiedBlockListenerPort));
    try {
      ServerSocket serverSocketVar = new ServerSocket(Blockchain.unverifiedBlockListenerPort, 6); //Bind to socket
      while (true) {
        socketVar = serverSocketVar.accept(); //Block wait til request.
        new UnverifiedBlockWorker(socketVar).start(); //Hand off client request to worker thread.
      }
    } catch (IOException ioe) { System.out.println(ioe); }
  }

  class UnverifiedBlockWorker extends Thread { // Worker for Unverified Socket RECV
    Socket socketVar;
    Block UVB = new Block(); //Temp var for received Unverified Block

    UnverifiedBlockWorker(Socket s) { socketVar = s; } //Socket from server thread

    @Override public void run() {
      try {
        ObjectInputStream unverifiedIn = new ObjectInputStream(socketVar.getInputStream());
        UVB = (Block) unverifiedIn.readObject(); // Read in the UVB as an object
        System.out.println(
            "[" + Blockchain.getProcString() + "] RECV UVB: " + UVB.getBlockTimestamp() + " " + UVB.getBlockData());
        Q.put(UVB); //Placed unverified blocks into the blocking queue for processing later on
        socketVar.close();
      } catch (Exception x) { x.printStackTrace(); }
    }
  }

}

//Updated Blockchain Handler
class BlockchainServer implements Runnable { //Server
  public void run() {
    Socket socketVar;
    System.out.println("[" + Blockchain.getProcString() + "] " + Blockchain.getCurrentTime()
        + " Starting Blockchain Server input thread using " + Blockchain.updatedBlockChainListenerPort);
    try {
      ServerSocket serverSocketVar = new ServerSocket(Blockchain.updatedBlockChainListenerPort, 6); //Bind to socket
      while (true) {
        socketVar = serverSocketVar.accept(); //Block wait til request.
        new BlockchainServerWorker(socketVar).start(); //Hand off client request to worker thread.
      }
    } catch (IOException ioe) { System.out.println(ioe); }
  }
}

class BlockchainServerWorker extends Thread { // DONE
  Socket socketVar;

  BlockchainServerWorker(Socket s) { socketVar = s; } 

  @Override public void run() {
    try {
      BufferedReader in = new BufferedReader(new InputStreamReader(socketVar.getInputStream())); //Socket data
      String originProc = in.readLine(); //Read Process string for origin of BC update
      String data = in.readLine(); //Read in BlockChainDS JSON 
      Gson g = new Gson(); //GSON for JSON
      BlockChainDS LT = g.fromJson(data, BlockChainDS.class); //Reconstruct Linked Tree
      BlockChainDS bc = new BlockChainDS(); //Construct replacement BCDS
      for (Block b : LT) bc.add(b); //Add all blocks from LT to newly created BCDS

      System.out.println("[" + Blockchain.getProcString() + "] BlockchainServerWorker RECV from " + originProc + " "
          + Blockchain.getCurrentTime());
      socketVar.close();

      //Update local class variable DS with newly created BCDS.
      Blockchain.BlockChain = bc;

      //P0 is responsible for updating the BlockchainLedger.json file 
      if (Blockchain.pNum == 0) Blockchain.generateJSONString(Blockchain.BlockChain, "BlockchainLedger.json"); 

      Blockchain.SLEEP(1);
    } catch (IOException x) {
      x.printStackTrace();
    }
  }
}

//Class that performs block verifying
class UnverifiedBlockConsumer implements Runnable {
  PriorityBlockingQueue<Block> Q; //Timestamp priority FIFO


  // Constructor binds our prioirty queue to the local variable.
  UnverifiedBlockConsumer(PriorityBlockingQueue<Block> Q) { this.Q = Q; } 

  public void run() {
    System.out.println(
        "[" + Blockchain.getProcString() + "] Starting the Unverified Block Priority Queue Consumer thread.\n");
    Gson g = new GsonBuilder().create(); //GSON FOR JSON

    try {
      while (true) {
        Block b = Q.take(); //Pop the next block to be verified based on timestamp
        if (b == null) break;
        if (Blockchain.BlockChain.doesBlockUUIDExistAlready(b)) continue; //If UUID has been verified, ignore.
          

        //Initialize the block with remaining data for verification
        b.setPrevBlockHash(Blockchain.BlockChain.lastAddedHash);
        b.setRandomSeed("12345");
        b.setVerifyingProcess(Integer.toString(Blockchain.pNum));

        
        b.VERIFY_BLOCK(); //Loop until favorable hash is achieved
        Blockchain.SLEEP(1); //Once favorable hash is achieved, sleep for 1 minute to sync process updates.
        
        b.setBlockID(Integer.toString(Integer.parseInt(Blockchain.BlockChain.getLastAddedBlockID()) + 1)); //Set bID to one higher than last added
        
        if (Blockchain.BlockChain.doesBlockUUIDExistAlready(b)) continue;//Check to see that UUID has not been added still just to be sure
          
        Blockchain.BlockChain.add(b); //Add block to blockchain
        String BLOCKCHAINJSON = g.toJson(Blockchain.BlockChain); //JSON-ify the BlockchainDS
        Multicast.BlockChainSend(BLOCKCHAINJSON); //Send updated ledger to peers.
        System.out.println("[" + Blockchain.getProcString() + "] " + "Successfully verified BlockID#" + b.getBlockID()
            + " and added to chain...sending to consortium...chain size is " + Blockchain.BlockChain.size());
        Blockchain.SLEEP(1); //Sleep to sync
      }
    } catch (Exception e) { System.out.println(e); }
  }
}

class Multicast { //Class for helpful functions to send messages to peers.
  private Multicast() { } //Empty constructor

  public static void KeySend(String KEYJSON) { //Responsible for sending KEYJSON to peers
    Socket socketVar;
    PrintStream serverPrintStream;
    int[] keyPorts = new int[] { 4710, 4711, 4712 }; //Public Key Ports

    int i;
    System.out.println(
        "[" + Blockchain.getProcString() + "] SEND " + Blockchain.getCurrentTime() + " is sending public keys...");
    for (i = 0; i < keyPorts.length; i++) {
      try {
        socketVar = new Socket("localhost", keyPorts[i]); //Connect to socket handler
        serverPrintStream = new PrintStream(socketVar.getOutputStream());
        serverPrintStream.println(KEYJSON); //Send JSON to peer
        serverPrintStream.flush();
        socketVar.close();
      } catch (Exception x) {
        System.out.println("[" + Blockchain.getProcString() + "] Couldn't connect to port " + keyPorts[i]);
      }
    }

  }

  public static void BlockChainSend(String BLOCKCHAINJSON) { //Responsible for sending BLOCKCHAINJSON to peers
    Socket socketVar;
    PrintStream serverPrintStream;
    int[] blockChainPorts = new int[] { 4930, 4931, 4932 }; //Blockchain Ports
    int i;
    System.out.println("[" + Blockchain.getProcString() + "] SEND " + Blockchain.getCurrentTime()
        + " is sending a new verified BlockChain...");
    for (i = 0; i < blockChainPorts.length; i++) {
      try {
        socketVar = new Socket("localhost", blockChainPorts[i]); //Connect to socket handler
        serverPrintStream = new PrintStream(socketVar.getOutputStream());
        serverPrintStream.println(Blockchain.getProcString()); //Send PROC string to peer
        serverPrintStream.println(BLOCKCHAINJSON); //Send JSON to peer
        serverPrintStream.flush();
        socketVar.close();
      } catch (Exception x) {
        System.out.println("[" + Blockchain.getProcString() + "] Couldn't connect to port " + blockChainPorts[i]);
      }
    }

  }

  public static void UnverifiedSend(String blockData) { //Responsible for sending KEYJSON to peers
    Socket serverSocketVar;
    String TimeStampString = Blockchain.getCurrentTime() + "." + Blockchain.getProcString(); //Timestamp with proc in string.
    int[] unverifiedPorts = new int[] { 4820, 4821, 4822 }; //UVB ports
    Block UVB = new Block(); //Init the UVB to be sent to peers.
    UVB.setBlockUUID();
    UVB.setBlockData(blockData);
    UVB.setBlockTimestamp(TimeStampString);
    ObjectOutputStream objectPrintStream = null;
    for (int i = 0; i < Blockchain.numProcesses; i++) {
      System.out.println("[" + Blockchain.getProcString() + "] RECV UVB: " + UVB.getBlockTimestamp() + " " + UVB.getBlockData());
      try {
        serverSocketVar = new Socket("localhost", unverifiedPorts[i]); //Connect to socket handlers
        objectPrintStream = new ObjectOutputStream(serverSocketVar.getOutputStream());
        objectPrintStream.writeObject(UVB); //Send UVB object to peer
        objectPrintStream.flush();
        serverSocketVar.close();
      } catch (Exception x) {
        System.out.println("[" + Blockchain.getProcString() + "] Couldn't connect to port " + unverifiedPorts[i]);
      }

    }

  }
}


//Driver class, "Main"
public class Blockchain { 
  
  static boolean hasNOTSentPKEY = true; //Used to force P0 and P1 to to wait for P2.
  static BlockChainDS BlockChain = new BlockChainDS(); //Main BlockChainDS var.
  static String PKEYJSON; //JSON of publickey
  static int numProcesses = 3; //Number of proccesses in the consortium
  static int pNum; //This proccess's unique identifier
  static int publicKeyListenerPort; //Public Key Listener Port
  static int unverifiedBlockListenerPort; //UVB Listener Port
  static int updatedBlockChainListenerPort; //BC Listener Port
  static Key[] publicKeyArray = new Key[3]; //Persistent DS for storing public keys
  static private ReentrantLock RL = new ReentrantLock(); // Mutex for threadsafe file writing.
  final static String GENSIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"; //Init hash
  final static String HASHING_ALGORITHM = "RSA"; //Algorithm of choice for hashing.
  final PriorityBlockingQueue<Block> ourPriorityQueue = new PriorityBlockingQueue<>(100, BlockTSComparator); //PCQ for Provider/consumer processes.


  public static Comparator<Block> BlockTSComparator = new Comparator<Block>() { //Comparator to define how timestamps are compared.
    @Override public int compare(Block b1, Block b2) {
      String s1 = b1.getBlockTimestamp();
      String s2 = b2.getBlockTimestamp();
      if (s1 == null) { return -1; }
      if (s2 == null) { return 1; }
      if (s1.equals(s2)) { return 0; }
      return s1.compareTo(s2);
    }
  };

  public static void SLEEP(long seconds) { //Helper function for easy sleeping
    System.out.println("\nSLEEPING for " + seconds + "\n");
    try {
      Thread.sleep(seconds * 1000);
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  
  public static KeyPair generateKP(String algorithm) throws Exception { //Helper function for generating KeyPair objects.
    Random rr = new Random();
    int rval = rr.nextInt(16777777);
    KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance(algorithm);
    SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
    rng.setSeed(rval); //Seed val for random generator
    keyGenerator.initialize(1024, rng);
    return keyGenerator.generateKeyPair();
  }

  public static void main(String argv[]) { //main 
    Blockchain s = new Blockchain();
    s.run(argv);
  }

  public void run(String argv[]) { //Actual main

    //Identifys process number based on CLI args.
    if (argv.length < 1) pNum = 0;
    else if (argv[0].equals("0")) pNum = 0;
    else if (argv[0].equals("1")) pNum = 1;
    else if (argv[0].equals("2")) pNum = 2;
    else pNum = 0;

    //Populates the bind ports based on processNum.
    publicKeyListenerPort = 4710 + pNum;
    unverifiedBlockListenerPort = 4820 + pNum;
    updatedBlockChainListenerPort = 4930 + pNum;


    try {
      KeyPair KP = generateKP(HASHING_ALGORITHM); //Generate KP 
      String publicKey = Blockchain.getPublicKeyString(KP); //Get Public Key
      String privateKey = Blockchain.getPrivateKeyString(KP); //Get Private Key


      //Display console welcome message
      System.out.println("----------------------------------------");
      System.out.println("[" + Blockchain.getProcString() + "] Hello from process number: " + pNum);
      System.out.println("[" + Blockchain.getProcString() + "] Public Key Listener: " + publicKeyListenerPort);
      System.out.println("[" + Blockchain.getProcString() + "] Unverified Blocks Listener: " + unverifiedBlockListenerPort);
      System.out.println("[" + Blockchain.getProcString() + "] Updated BlockChain Listener: " + updatedBlockChainListenerPort);
      System.out.println("[" + Blockchain.getProcString() + "] Public Key: " + publicKey);
      System.out.println("[" + Blockchain.getProcString() + "] Private Key: " + privateKey);
      System.out.println("----------------------------------------\n");
      Key PKEY = new Key(Integer.toString(pNum), publicKey); //Helper key object for marshalling PKEYs to other nodes.
      // Gson g = new GsonBuilder().setPrettyPrinting().create(); //For humans
      Gson g = new GsonBuilder().create(); //GSON for JSON
      PKEYJSON = g.toJson(PKEY); //Public Key in JSON form.

      new Thread(new PublicKeyServer()).start(); //Public Key Handler Thread
      new Thread(new UnverifiedBlockServer(ourPriorityQueue)).start(); // UVB Handler Thread
      new Thread(new BlockchainServer()).start(); // BC Handler Thread

      Blockchain.SLEEP(2);

      if (pNum == 2) { //Start off the program by allowing P2 to send public keys
        Blockchain.hasNOTSentPKEY = false; // now it has..
        Multicast.KeySend(PKEYJSON);
      }

      while (hasNOTSentPKEY) { //While loop to catch P0 and P1 and force them to wait til P2 joins.
        System.out.println("Waiting for P2 to send public keys...");
        Blockchain.SLEEP(1);
      }

      Blockchain.SLEEP(5); //Re-sync

      String INPUT_FILE_CONVENTION = "BlockInput"; //Block input file name
      String INPUT_FILE_EXTENSION = ".txt";
      ArrayList<String> dataInput = new ArrayList<String>(); //Tempvar for reading raw data

      String blockInputFileName = INPUT_FILE_CONVENTION + Integer.toString(pNum) + INPUT_FILE_EXTENSION; //Process-specific file
      System.out.println("[" + Blockchain.getProcString() + "] " + "Reading unverified data from " + blockInputFileName);
      ArrayList<String> temp = readInputFile(blockInputFileName); //Helper function to read input from file
      
      for (String s : temp) dataInput.add(s); //Iterate over carved data and store for Multicast.

      System.out.println("[" + Blockchain.getProcString() + "] 1 file ingested..." + dataInput.size() + " unverified blocks ready...");

      Blockchain.SLEEP(5); //Re-sync

      for (String s : dataInput) {
        Multicast.UnverifiedSend(s); //Send peers known UVBs
        Blockchain.SLEEP(1); //Re-sync, and to help randomize timestamps
      }

      Blockchain.SLEEP(5); //Re-sync

      // BUILDS GENESIS BLOCK
      System.out.println("[" + Blockchain.getProcString() + "] " + "Building the genesis block...");
      Block genesisRecord = Blockchain.generateGenesisBlock(); //Dummy genesis block
      Blockchain.BlockChain.add(genesisRecord); //Add genesis block to BCDS

      //Winning hashes must start with an integer.
      System.out.println("[" + Blockchain.getProcString() + "] "
          + "Building the block chain...ALL verified block hashes must NOT start with 'a', 'b', 'c', 'd', 'e', or 'f'.");

      Blockchain.SLEEP(5); //Re-sync

      new Thread(new UnverifiedBlockConsumer(ourPriorityQueue)).start(); //Start Consumer thread
    } catch (Exception e) { e.printStackTrace(); }
  }

  public static Block generateGenesisBlock() { //Generate genesis block helper function
     return new Block("-1", GENSIS_HASH, "Genesis Block 9999.99.99 999-99-999 99999 999999 999999999", "12345"); 
    }

  public static String generateJSONString(BlockChainDS a, String fileName) { //Creates a JSON string, and writes it as a file on disk
    try {
      RL.lock(); //Lock this critical section for thread safety.
      Gson g = new GsonBuilder().setPrettyPrinting().create();
      writeJSONStringToDisk(g, a, fileName); //Write to disk
      return g.toJson(a); //Return string if needed.
    } finally {
      RL.unlock(); //Unlock critical section
    }
  }

  public static void writeJSONStringToDisk(Gson g, BlockChainDS a, String fileName) { //Helper function to write file to disk
    try (FileWriter writer = new FileWriter(fileName)) {
      g.toJson(a, writer);
    } catch (IOException e) { e.printStackTrace(); }
  }

  public ArrayList readInputFile(String fileName) { //Helper function to read input from files on disk, such as BlockInput
    ArrayList AL = new ArrayList<String>();
    File f = new File(fileName);
    try {
      BufferedReader reader = new BufferedReader(new FileReader(f));
      String temp;
      try {
        while ((temp = reader.readLine()) != null) AL.add(temp);
      } catch (IOException io) { io.printStackTrace(); }
    } catch (FileNotFoundException fnf) { fnf.printStackTrace(); }
    return AL;
  }

  public static String getProcString() { return "(P" + Blockchain.pNum + ")"; } //Helper function for console messages.
  public static String getCurrentTime() { return String.format("%1$s%2$tF.%2$tT", "", new Date()); } //Helper function for currentTime

  //Public key conversion functions
  public static byte[] getPublicKeyBytes(KeyPair KP) { return KP.getPublic().getEncoded(); } 
  public static String getPublicKeyString(KeyPair KP) { return Base64.getEncoder().encodeToString(Blockchain.getPublicKeyBytes(KP)); }

  //Private key conversion functions.
  public static byte[] getPrivateKeyBytes(KeyPair KP) { return KP.getPrivate().getEncoded(); }
  public static String getPrivateKeyString(KeyPair KP) { return Base64.getEncoder().encodeToString(Blockchain.getPrivateKeyBytes(KP)); }
}
