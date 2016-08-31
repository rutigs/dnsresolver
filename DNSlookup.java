
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.Byte;
import java.lang.Exception;
import java.lang.String;
import java.net.*;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.Random;
import java.nio.ByteBuffer;
import java.math.BigInteger;
import java.util.Random;
import java.util.ArrayList;
import java.util.regex.Pattern;
/**
 *
 */

/**
 * @author Donald Acton
 * This example is adapted from Kurose & Ross
 *
 */
public class DNSlookup {


    static final int MIN_PERMITTED_ARGUMENT_COUNT = 2;
    static boolean tracingOn = false;
    static InetAddress rootNameServer;
    static String queryID;
    static String fqdn;
    static int queries = 0;
    static InetAddress originalRNS;
//    static ArrayList<ResponseRecord> answerList;
//    static ArrayList<ResponseRecord> nameServerList;
//    static ArrayList<ResponseRecord> additionalList;

    static class ResponseRecord {
        public String name;
        public int type;
        public int rClass;
        public String ttl;
        public String rData;

        public ResponseRecord(String name, int type, int rClass, String ttl, String rData) {
            this.name = name;
            this.type = type;
            this.rClass = rClass;
            this.ttl = ttl;
            this.rData = rData;
        }

        public String toString() {
            return (this.name + " " +  this.type + " " +  this.rClass + " " +  this.ttl + " " +  this.rData);
        }

        public String getRecordValueAsString() {

            String recordType = getTypeAsString(this.type);

            String recordValue = "";
            if(!recordType.equals("AAAA")) {
                if(this.rData.contains(".")) {
                    String[] recordValueArr = this.rData.split(Pattern.quote("."));
                    for(String s : recordValueArr) {
                        for(int i = 0; i < s.length(); i+=2) {
                            String str = s.substring(i, i+2);
                            recordValue += ((char) Integer.parseInt(str, 16));
                        }
                        recordValue += ".";
                    }
                    recordValue = recordValue.substring(0, recordValue.length()-1);
                } else {
                    //System.out.println(rData);
                    for(int i = 0; i < this.rData.length(); i+=2) {
                        String str = this.rData.substring(i, i+2);
                        //recordValue += (Integer.parseUnsignedInt(str, 16));
                        recordValue += (int) Long.parseLong(str, 16);
                        recordValue += ".";
                    }
                    recordValue = recordValue.substring(0, recordValue.length()-1);
                }
            } else {
                //System.out.println(this.rData);
                for(int i = 0; i < 8; i++) {
                    String s = (rData.substring(i*4, (i+1)*4)).replaceFirst("^0*", "");
                    if (s.isEmpty())
                        s = "0";
                    recordValue += s;
                    recordValue += ":";
                }
                recordValue = recordValue.substring(0, recordValue.length()-1);
            }
            return recordValue;
        }

        public String getRecordNameAsString() {
            String recordName = "";
            if(this.name.contains(".")) {
                String[] recordNameArr = this.name.split(Pattern.quote("."));
                for(String s : recordNameArr) {
                    for(int i = 0; i < s.length(); i+=2) {
                        String str = s.substring(i, i+2);
                        recordName += ((char) Integer.parseInt(str, 16));
                    }
                    recordName += ".";
                }
                recordName = recordName.substring(0, recordName.length()-1);
            } else {
                for(int i = 0; i < this.name.length(); i+=2) {
                    String str = this.name.substring(i, i+2);
                    recordName += ((char) Integer.parseInt(str, 16));
                }
            }
            return recordName;
        }

        public void printRecord() {

            String recordName = getRecordNameAsString();
            String recordType = getTypeAsString(this.type);
            String recordValue = getRecordValueAsString();

            System.out.format("       %-30s %-10d %-4s %s\n", recordName, Integer.valueOf(this.ttl, 16),
                    recordType, recordValue);
        }

        public static String getTypeAsString(int type) {
            String result = "";
            switch (type) {
                case 1:
                    result = "A";
                    break;
                case 2:
                    result = "NS";
                    break;
                case 5:
                    result = "CN";
                    break;
                case 15:
                    result = "MX";
                    break;
                case 28:
                    result = "AAAA";
                    break;
                default:
                    result = "-1";
            }
            return result;
        }
    }
    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {
        //String fqdn;

        int argCount = args.length;

        if (argCount < 2 || argCount > 3) {
            usage();
            return;
        }

        rootNameServer = InetAddress.getByName(args[0]);
        fqdn = args[1];
        originalRNS = rootNameServer;

        if (argCount == 3 && args[2].equals("-t"))
            tracingOn = true;

        beginQuerying(rootNameServer, fqdn);
    }

    public static void beginQuerying(InetAddress rootNameServer, String fqdn) throws Exception {
        byte[] dnsQuery = encode(fqdn);
        DatagramPacket dnsQueryPacket = new DatagramPacket(dnsQuery, dnsQuery.length);

        //System.out.println("FQDN @ RootNameServer " + fqdn + " @ " + rootNameServer.toString());
        dnsQueryPacket = new DatagramPacket(dnsQuery, dnsQuery.length, rootNameServer, 53);

        DatagramSocket dnsSocketOut = new DatagramSocket(1994+queries);
        contactRootServer(dnsQueryPacket, dnsSocketOut);

        byte[] dnsResponseBytes = new byte[512];
        DatagramPacket dnsResponsePacket = new DatagramPacket(dnsResponseBytes, dnsResponseBytes.length);
        //DatagramSocket dnsSocketIn = new DatagramSocket(2004);

        String decodedResponse;

        try {
            //System.out.println("Waiting for a response...");
            //dnsSocketIn.receive(dnsResponsePacket);
            dnsSocketOut.setSoTimeout(5000);
            dnsSocketOut.receive(dnsResponsePacket);
            dnsResponseBytes = dnsResponsePacket.getData();
            decodedResponse = decode(dnsResponseBytes, queryID, rootNameServer, fqdn);
        } catch (SocketTimeoutException e) {
            //System.out.println(e);
            dnsQuery = encode(fqdn);
            dnsQueryPacket = new DatagramPacket(dnsQuery, dnsQuery.length, rootNameServer, 53);
            contactRootServer(dnsQueryPacket, dnsSocketOut);
            try {
                dnsSocketOut.receive(dnsResponsePacket);
                dnsResponseBytes = dnsResponsePacket.getData();
                decodedResponse = decode(dnsResponseBytes, queryID, rootNameServer, fqdn);
            } catch (SocketTimeoutException e2) {
                //System.out.println(e2);
                printErr(6);
            }
        }

    }

    private static void usage() {
        System.out.println("Usage: java -jar DNSlookup.jar rootDNS name [-t]");
        System.out.println("   where");
        System.out.println("       rootDNS - the IP address (in dotted form) of the root");
        System.out.println("                 DNS server you are to start your search at");
        System.out.println("       name    - fully qualified domain name to lookup");
        System.out.println("       -t      -trace the queries made and responses received");
    }

    public static byte[] encode(String fqdn) {
        // convert the given fqdn into a byte with proper dns format
        //int len = fqdn.length();
        // for testing purposes: www.ugrad.cs.ubc.ca
        //String s = "2b2b0000000100000000000003777777057567726164026373037562630263610000010001";

        Random rand = new Random();
        int randomNum = rand.nextInt(65535) + 1;
        queryID = Integer.toHexString(randomNum);
        String queryString = queryID;

        String defaultInfo = "00000001000000000000";
        queryString += defaultInfo;

        String encodedFqdn = "";
        String[] fqdnParts = fqdn.split(Pattern.quote("."));
        for(int i = 0; i < fqdnParts.length; i++) {
            String part = "";
            try {
                part = String.format("%040x", new BigInteger(1, fqdnParts[i].getBytes("UTF-8")));
                part = part.replaceFirst("^0*", "");
            } catch (UnsupportedEncodingException e) {}
            //String part = String.format("%040x", new BigInteger(1, fqdnParts[i].getBytes("UTF-8")));
            encodedFqdn += "0" + fqdnParts[i].length();
            encodedFqdn += part;
        }
        encodedFqdn += "00";
        //System.out.println("Encoded FQDN " + encodedFqdn);
        queryString += encodedFqdn;

        String defaultQueryEnd = "00010001";
        queryString += defaultQueryEnd;

        byte[] dnsQuery2 = new BigInteger(queryString, 16).toByteArray();

        return dnsQuery2;
    }

    public static void contactRootServer(DatagramPacket dnsQuery, DatagramSocket dnsSocket) {
        try {
            dnsSocket.send(dnsQuery);
        } catch (IOException e) {
            System.out.println(e);
        }
    }

    public static String decode(byte[] dnsResponse, String queryID, InetAddress rootNameServer, String fqdn) {

        ArrayList<ResponseRecord> answerList = new ArrayList<ResponseRecord>();
        ArrayList<ResponseRecord> nameServerList = new ArrayList<ResponseRecord>();
        ArrayList<ResponseRecord> additionalList = new ArrayList<ResponseRecord>();

        String s = "";
        s = bytesToHex(dnsResponse);

        String qID = s.substring(0, 4);
        String qr = s.substring(4, 6);

        boolean auth = false;
        String checkAA = qr.substring(1,qr.length());
        int checkAAVal = Integer.valueOf(checkAA, 16);
        if(checkAAVal >= 4) {
            auth = true;
        }

        int qCount = Integer.valueOf(s.substring(8, 12), 16);
        int aCount = Integer.valueOf(s.substring(12, 16), 16);
        int nsCount = Integer.valueOf(s.substring(16, 20), 16);
        int arCount = Integer.valueOf(s.substring(20, 24), 16);

        String qName = "";
        int next = Integer.valueOf(s.substring(24, 26), 16);
        String temp = s.substring(26, s.length());
        while(next != 0) {
            qName += temp.substring(0, next*2);
            qName += ".";
            temp = temp.substring(next*2, temp.length());
            next = Integer.valueOf(temp.substring(0, 2), 16);
            temp = temp.substring(2, temp.length());
        }
        //System.out.println("qName: " + qName);
        qName = qName.substring(0, qName.length() - 1);
        
        String[] recordValueArr = qName.split(Pattern.quote("."));
        qName = "";
        for(String t : recordValueArr) {
            for(int i = 0; i < t.length(); i+=2) {
                String str = t.substring(i, i+2);
                qName += ((char) Integer.parseInt(str, 16));
            }
            qName += ".";
        }
        qName = qName.substring(0, qName.length()-1);
        
        String qType = temp.substring(0, 4);
        String qClass = temp.substring(4, 8);

        temp = temp.substring(8, temp.length());

        for (int i = 0; i < aCount; i++) {
            temp = createResponseRecord(temp, s, answerList);
        }

        for (int i = 0; i < nsCount; i++) {
            temp = createResponseRecord(temp, s, nameServerList);
        }

        for (int i = 0; i < arCount; i++) {
            temp = createResponseRecord(temp, s, additionalList);
        }
        
        printResult(queryID, qName, rootNameServer, fqdn, qID, auth, answerList, nameServerList, additionalList);

        queries++;

        //System.out.println(answerList.size());
        //System.out.println(queries);
        String newRNS = rootNameServer.toString();
        InetAddress newRNSIP = originalRNS;
        String newFQDN = fqdn;
        if(queries < 30) {
            if(answerList.size() == 0) {
                //System.out.println("recursive checking!");
                if (additionalList.size() > 0) {
                    try {
                        newRNS = additionalList.get(0).getRecordValueAsString();
                        newRNSIP = InetAddress.getByName(newRNS);
                    } catch (UnknownHostException e) {
                        // do nuthin'
                    }
                } else {
                    newFQDN = nameServerList.get(0).getRecordValueAsString();
                }
                //rootNameServer = newRNSIP;
                try {
                    //System.out.println("Attempting recursive query with new RNS: " + rootNameServer.toString());
                    beginQuerying(newRNSIP, newFQDN);
                } catch (Exception e) {
                    System.out.println(e);
                }
            } else if(answerList.get(0).getRecordValueAsString().equals("CN")) {
                newFQDN = answerList.get(0).getRecordValueAsString();
                try {
                    beginQuerying(newRNSIP, newFQDN);
                } catch (Exception e) {
                    // do nothing
                }
            }
        }

        return s;
    }

    public static String createResponseRecord(String temp, String original, ArrayList<ResponseRecord> arr) {
        String nameCheck = temp.substring(0, 2);
        String name = "";
        if(nameCheck.equals("C0")) {
            name = decompress(original, temp.substring(2, 4));
            temp = temp.substring(4, temp.length());
        } else if(nameCheck.startsWith("0")) {
            int next = Integer.valueOf(temp.substring(1, 2), 16);
            temp = temp.substring(2, temp.length());
            while(next != 0) {
                name += temp.substring(0, next*2);
                name += ".";
                temp = temp.substring(next*2, temp.length());
                next = Integer.valueOf(temp.substring(0, 2), 16);
                temp = temp.substring(2, temp.length());
            }
            name = name.substring(0, name.length() - 1);
        }

        // if no name is given we are assuming 00 is given before class and type
        //System.out.println("Type: " + temp.substring(0,4));
        int type = Integer.valueOf(temp.substring(0, 4), 16);
        int rclass = Integer.valueOf(temp.substring(4, 8), 16);
        String ttl = temp.substring(8, 16);
        int rDataLength = Integer.valueOf(temp.substring(16, 20), 16);
        String rData = temp.substring(20, 20 + (rDataLength * 2));

        //System.out.println("Rdata: " + rData);

        if(rData.contains("C0")) {
            String nextByte = rData.substring(rData.indexOf("C0")+2, rData.indexOf("C0")+4);
            if(Integer.valueOf(nextByte, 16) > 12) {
                //String result = rData;
                //System.out.println(rData);
                String result = decompress(original, rData.substring(rData.indexOf("C0") + 2, rData.indexOf("C0") + 4));
                //System.out.println("Result: " + result);

                if(result.length() <= 32) {
                    rData = rData.replace(rData.substring(rData.indexOf("C0"), rData.indexOf("C0") + 4), result);
                }

                //rData = rData.replace(rData.substring(rData.indexOf("C0"), rData.indexOf("C0") + 4), result);
            }
        }
        //System.out.println("Rdata: " + rData);
        temp = temp.substring(20 + (rDataLength * 2), temp.length());

        rData = cleanRData(rData, type);

        ResponseRecord r = new ResponseRecord(name, type, rclass, ttl, rData);
        arr.add(r);
        return temp;
    }

    public static String cleanRData(String rData, int type) {

        if(rData.startsWith("00")) {
            return rData;
        }
        //System.out.println(rData);
        //System.out.println(type);
        String result = "";

        int next = Integer.valueOf(rData.substring(0,2), 16);
        if(!rData.startsWith("0"))
        {
            return rData;
        }
        result += rData.substring(2, next*2 + 2);
        result += ".";
        rData = rData.substring(next * 2 + 2, rData.length());
        if(rData.startsWith("0")) {
            result += cleanRData(rData, type);
        } else {
            result += rData;
        }

        //System.out.println("Result: " + result);
        return result;
    }

    public static String decompress(String original, String index) {
//        System.out.println("Original: " + original);
//        System.out.println("Index: " + index);

        String data = "";

        int nextInt = Integer.valueOf(index, 16);
        String nextString = original.substring(nextInt * 2, nextInt * 2 + 2);

        int next = Integer.valueOf(nextString, 16);
        String temp = original.substring(Integer.valueOf(index, 16)*2 + 2, original.length());
        while(next != 0) {
            data += temp.substring(0, next * 2);
            data += ".";
            temp = temp.substring(next * 2, temp.length());
            next = Integer.valueOf(temp.substring(0, 2), 16);
            if (next == 192)
            {
                String result = decompress(original, temp.substring(temp.indexOf("C0") + 2, temp.indexOf("C0") + 4));
                data += result;
                temp = temp.substring(4, temp.length());
                break;
            }
            else
                temp = temp.substring(2, temp.length());
        }
        if(data.endsWith(".")) {
            data = data.substring(0, data.length() - 1);
        }
        // System.out.println("Compressed result: " + data);

        if(data.equals(""))
            data = "C0" + index;
        return data;
    }

    public static void printErr(int errCode) {
        String errType = "";
        switch(errCode) {
            case 1:
                errType = "4";
                break;
            case 2:
                errType = "4";
                break;
            case 3:
                errType = "1";
                break;
            case 4:
                errType = "4";
                break;
            case 5:
                errType = "4";
                break;
            // lookup times out
            case 6:
                errType = "2";
                break;
            // too many queries attempted
            case 7:
                errType = "3";
                break;
            default:
                errType = "4";
        }
        System.out.println(fqdn + " -" + errType + " 0.0.0.0");
    }
    
    public static void printResult(String queryID, String qName, InetAddress rts, String fqdn, String qID, boolean isAuth,
    ArrayList<ResponseRecord> ans, ArrayList<ResponseRecord> ns, ArrayList<ResponseRecord> adl) {
        String formatRTS = rts.toString();
        if(tracingOn) {
            System.out.println();
            System.out.println();
            System.out.println("QueryID:\t" + queryID.toUpperCase() + " " + fqdn + " --> " + formatRTS.substring(1, formatRTS.length()));
            System.out.println("Response ID:\t" + qID + " Authoritative = " + isAuth);
            System.out.println("  Answers (" + ans.size() + ")");
            for (int i = 0; i < ans.size(); i++) {
                ans.get(i).printRecord();
            }
            System.out.println("  Name Servers (" + ns.size() + ")");
            for (int i = 0; i < ns.size(); i++) {
                ns.get(i).printRecord();
            }
            System.out.println("  Additional Information (" + adl.size() + ")");
            for (int i = 0; i < adl.size(); i++) {
                adl.get(i).printRecord();
            }
        }
        if((ans.size() > 0) && (getTypeAsString(ans.get(0).type) != "CN")) {
            System.out.println(qName + " " + Integer.valueOf(ans.get(0).ttl, 16) + " " + ans.get(0).getRecordValueAsString());
        }
    }   

    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
    // s/o to stack overflow helping a brother out
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static String getTypeAsString(int type) {
        String result = "";
        switch (type) {
            case 1:
                result = "A";
                break;
            case 2:
                result = "NS";
                break;
            case 5:
                result = "CN";
                break;
            case 15:
                result = "MX";
                break;
            case 28:
                result = "AAAA";
                break;
            default:
                result = "-1";
        }
        return result;
    }
}