package schnorr.reductions;

import java.math.BigInteger;

import dlog.DLog_Challenge;
import dlog.I_DLog_Challenger;
import genericGroups.IGroupElement;
import schnorr.I_Schnorr_EUFNMA_Adversary;
import schnorr.Schnorr_PK;
import utils.Pair;

// Own imports
import java.security.SecureRandom;
import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.HashSet;

public class Schnorr_EUFNMA_Reduction extends A_Schnorr_EUFNMA_Reduction{

    private IGroupElement generator;
    private IGroupElement x;
    private BigInteger p;

    private SecureRandom random = new SecureRandom();
    private Map<String, BigInteger> hashes = new HashMap<String, BigInteger>();
    private Set<BigInteger> usedHashes = new HashSet<BigInteger>();

    public Schnorr_EUFNMA_Reduction(I_Schnorr_EUFNMA_Adversary<IGroupElement, BigInteger> adversary) {
        super(adversary);
        //Do not change this constructor!
    }

    @Override
    public Schnorr_PK<IGroupElement> getChallenge() {
        //Write your Code here!
        return new Schnorr_PK<IGroupElement>(this.generator, this.x);   // PK = x = g^y
    }

    @Override
    public BigInteger hash(String message, IGroupElement r) {
        //Write your Code here!
        var key = message;
        if (hashes.containsKey(key)) {
            return hashes.get(key);
        } 
        
        var hash = utils.NumberUtils.getRandomBigInteger(this.random, this.p);
        
        while (usedHashes.contains(hash)) {
            // Need to make sure that c1 != c2
            // TODO: is this really needed???
            hash = utils.NumberUtils.getRandomBigInteger(this.random, this.p);
        }

        hashes.put(key, hash);
        usedHashes.add(hash);
        return hash;
    }

    @Override
    public BigInteger run(I_DLog_Challenger<IGroupElement> challenger) {
        //Write your Code here!
        var seed = 12345;

        DLog_Challenge<IGroupElement> challenge = challenger.getChallenge();      
        this.generator = challenge.generator;
        this.x = challenge.x;       // = g^y    --> goal: find y
        this.p = challenge.generator.getGroupOrder();

        adversary.reset(seed);
        var result1 = adversary.run(this);
        
        this.hashes.clear();
        adversary.reset(seed);
        var result2 = adversary.run(this);

        if (result1 == null) {
            System.out.println("Result1 null");
            return BigInteger.ZERO;
        }
        
        if (result2 == null) {
            System.out.println("Result2 null");
            return BigInteger.ZERO;
        }

        var s1 = result1.signature.s;
        var s2 = result2.signature.s;
        var c1 = result1.signature.c;
        var c2 = result2.signature.c;

        // y = (s1 - s2) / (c1 - c2)
        var numerator = s1.subtract(s2).mod(this.p);
        var denominator = c1.subtract(c2).modInverse(this.p);
        var secret = numerator.multiply(denominator).mod(this.p);

        return secret;
    }
    
}
