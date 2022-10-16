package katzwang.reductions;

import java.math.BigInteger;
import java.util.Random;

import ddh.I_DDH_Challenger;
import genericGroups.GroupElement;
import genericGroups.IGroupElement;
import katzwang.A_KatzWang_EUFNMA_Adversary;
import katzwang.KatzWangPK;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

// Own imports
import java.util.Map;
import java.util.HashMap;
import java.security.SecureRandom;

public class KatzWang_EUFNMA_Reduction extends A_KatzWang_EUFNMA_Reduction {

    private IGroupElement x;
    private IGroupElement y;
    private IGroupElement z;
    private IGroupElement generator;
    private BigInteger p;

    private SecureRandom random = new SecureRandom();
    private Map<Triple<IGroupElement, IGroupElement, String>, BigInteger> hashes 
        = new HashMap<Triple<IGroupElement, IGroupElement, String>, BigInteger>();

    public KatzWang_EUFNMA_Reduction(A_KatzWang_EUFNMA_Adversary adversary) {
        super(adversary);
        // Do not change this constructor!
    }

    @Override
    public Boolean run(I_DDH_Challenger<IGroupElement, BigInteger> challenger) {
        // Write your Code here!
        var challenge = challenger.getChallenge();
        this.x = challenge.x;
        this.y = challenge.y;
        this.z = challenge.z;
        this.generator = challenge.generator;
        this.p = challenge.generator.getGroupOrder();

        var result = adversary.run(this);

        if (result == null) {
            //System.out.println("Result is null");
            return false;
        }

        var c = result.signature.c;
        var s = result.signature.s;

        // g^s * y1^(-c)    --> in our case with y1 = g^x, this is = g^s * g^-cx = g^r
        var gr = this.generator.power(s).multiply(this.x.power(c.negate()));

        // h^s * y2^(-c)   --> in our case with h = g^y and y2 = g^xy, this is = g^ys * g^-cxy = g^yr = h^r
        var hr = this.y.power(s).multiply(this.z.power(c.negate()));

        return hash(gr, hr, result.message).equals(c);
    }

    @Override
    public KatzWangPK<IGroupElement> getChallenge() {
        // Write your Code here!
        // PK = (g, h, y1=g^x, y2=h^x)  --> PK = (g, g^y, g^x, g^z=g^xy)
        return new KatzWangPK<IGroupElement>(this.generator, this.y, this.x, this.z);
    }

    @Override
    public BigInteger hash(IGroupElement comm1, IGroupElement comm2, String message) {
        // Write your Code here!
        var key = new Triple<IGroupElement, IGroupElement, String>(comm1, comm2, message);
        if (hashes.containsKey(key)) {
            return hashes.get(key);
        } 
        
        var hash = utils.NumberUtils.getRandomBigInteger(this.random, this.p);

        hashes.put(key, hash);
        return hash;
    }

}
