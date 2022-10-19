package cdh_quadratic;

import java.math.BigInteger;
import java.util.Random;

import cdh.CDH_Challenge;
import cdh.I_CDH_Challenger;
import genericGroups.GroupElement;
import genericGroups.IGroupElement;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

// Own imports
import java.util.List;
import java.util.ArrayList;

/**
 * This is the file you need to implement.
 * 
 * Implement the methods {@code run} and {@code getChallenge} of this class.
 * Do not change the constructor of this class.
 */
public class CDH_Quad_Reduction extends A_CDH_Quad_Reduction<IGroupElement> {

    private IGroupElement g;
    private IGroupElement x;
    private IGroupElement y;
    private BigInteger p;
    private BigInteger pMinus3;

    private IGroupElement currX;
    private IGroupElement currY;

    private IGroupElement g0;           // g^0
    private IGroupElement gd;           // g^d
    private IGroupElement gdInverse;    // g^(-d)
    private IGroupElement gb;           // g^b
    private IGroupElement ga;           // g^a
    private IGroupElement gc;           // g^c
    
    private List<Pair<BigInteger, IGroupElement>> intermediateResults;       // (exponent -> g^(a^exponent))

    /**
     * Do NOT change or remove this constructor. When your reduction can not provide
     * a working standard constructor, the TestRunner will not be able to test your
     * code and you will get zero points.
     */
    public CDH_Quad_Reduction() {
        // Do not add any code here!
    }

    @Override
    public IGroupElement run(I_CDH_Challenger<IGroupElement> challenger) {
        // This is one of the both methods you need to implement.

        // By the following call you will receive a DLog challenge.
        CDH_Challenge<IGroupElement> challenge = challenger.getChallenge();

        this.g = challenge.generator;
        this.g0 = this.g.power(BigInteger.ZERO);
        this.x = challenge.x;
        this.y = challenge.y;
        this.p = challenge.generator.getGroupOrder();
        this.pMinus3 = this.p.subtract(BigInteger.valueOf(3));

        if (this.x.equals(this.g)) {
            return this.y;
        }

        if (this.y.equals(this.g)) {
            return this.x;
        }

        // your reduction does not need to be tight. I.e., you may call
        // adversary.run(this) multiple times.

        var gaxy = gaxy();                // g^(axy)
        var gapMinus3 = gapMinus3();    // g^(a^(p-3)) = g^(1/a^2)

        this.currX = gaxy;
        this.currY = gapMinus3;
        var res = adversary.run(this);      // g^(a^2*xy*1/a^2 + baxy + c*1/a^2 + d)    = g^(xy + baxy + c*1/a^2 + d)

        this.currX = gaxy;
        this.currY = this.g0;
        var t1 = adversary.run(this).multiply(this.gdInverse).invert();      // g^(baxy)

        this.currX = this.g0;
        this.currY = gapMinus3;
        var t2 = adversary.run(this).multiply(this.gdInverse).invert();      // g^(c*1/a^2)

        // Remember that this is a group of prime order p.
        // In particular, we have a^(p-1) = 1 mod p for each a != 0.

        return res.multiply(t1).multiply(t2).multiply(this.gdInverse);
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {
        // This is the second method you need to implement.
        // You need to create a CDH challenge here which will be given to your CDH
        // adversary.
        
        // Instead of null, your cdh challenge should consist of meaningful group
        // elements.
        return new CDH_Challenge<IGroupElement>(this.g, this.currX, this.currY);
    }

    private IGroupElement f1() {
        // return g^(axy + bx + cy + d)
        this.currX = this.x;
        this.currY = this.y;
        return adversary.run(this);
    }

    private IGroupElement f2() {
        // return f^(axy + bx + cy) = f1 / g^d
        var f1 = f1();

        this.currX = this.g0;
        this.currY = this.g0;
        this.gd = adversary.run(this);
        this.gdInverse = this.gd.invert();
        return f1.multiply(this.gdInverse);
    }

    private IGroupElement f3() {
        // return f^(axy + bx) = f2 / g^cy
        var f2 = f2();

        this.currX = this.g0;
        this.currY = this.y;
        var gcy = adversary.run(this).multiply(this.gdInverse);      // g^(cy)
        return f2.multiply(gcy.invert());
    }

    private IGroupElement gaxy() {
        // return g^(axy)
        var f3 = f3();

        this.currX = this.x;
        this.currY = this.g0;
        var gbx = adversary.run(this).multiply(this.gdInverse);      // g^(bx)
        return f3.multiply(gbx.invert());
    }

    private IGroupElement gapMinus3() {
        // calculate g^(a^(p-3)) = g^(1/(a^2))
        this.intermediateResults = new ArrayList<Pair<BigInteger, IGroupElement>>();

        this.currX = this.g;
        this.currY = this.g;
        var gabcd = adversary.run(this);        // g^(a + b + c + d)

        this.currX = this.g;
        this.currY = this.g0;
        this.gb = adversary.run(this).multiply(this.gdInverse);     // g^b

        this.currX = this.g0;
        this.currY = this.g;
        this.gc = adversary.run(this).multiply(this.gdInverse);     // g^c

        this.ga = gabcd.multiply(this.gb.invert()).multiply(this.gc.invert()).multiply(this.gdInverse);     // g^a

        this.intermediateResults.add(new Pair<BigInteger,IGroupElement>(BigInteger.ONE, this.ga));

        var exponent = BigInteger.valueOf(3);
        var current = this.ga;

        while (exponent.compareTo(this.pMinus3) < 0) {
            // use g^a^exponent to get g^(a^(1 + 2*exponent)), using (g, g^a^exponent, g^a^exponent)
            this.currX = current;
            this.currY = current;
            var next = adversary.run(this);      // g^(a^(1 + 2*exponent) + ba^exponent + ca^exponent + d)

            this.currX = current;
            this.currY = this.g0;
            var tempB = adversary.run(this).multiply(this.gdInverse).invert();
            
            this.currX = this.g0;
            this.currY = current;
            var tempC = adversary.run(this).multiply(this.gdInverse).invert();

            current = next.multiply(tempB).multiply(tempC).multiply(this.gdInverse);        // g^(a^(1 + 2*exponent))
            this.intermediateResults.add(new Pair<BigInteger,IGroupElement>(exponent, current));

            exponent = BigInteger.ONE.add(exponent.multiply(BigInteger.TWO));
        }

        return combinePMinus3(this.pMinus3, this.intermediateResults.size() - 1);
    }

    private IGroupElement combinePMinus3(BigInteger exponent, int left) {
        if (BigInteger.ZERO.equals(exponent)) {
            // return g^a^0 = g^1 = g
            return this.g;
        }

        if (BigInteger.ONE.equals(exponent)) {
            // return g^a^1 = g^a
            return this.ga;
        }

        if (BigInteger.TWO.equals(exponent)) {
            // return g^a^2
            this.currX = this.ga;
            this.currY = this.g0;
            var gba = adversary.run(this).multiply(this.gdInverse);     // g^(ba)

            this.currX = this.ga;
            this.currY = this.g;
            return adversary.run(this).multiply(gba.invert()).multiply(this.gc.invert()).multiply(this.gdInverse);
        }

        while(this.intermediateResults.get(left).first.compareTo(exponent) > 0) {
            left--;
        }

        var current = this.intermediateResults.get(left);

        if (current.first.equals(exponent)) {
            return current.second;
        }

        var tmp = combinePMinus3(exponent.subtract(BigInteger.ONE.add(current.first)), left);      // g(a^(exponent - (1 + current)))

        this.currX = current.second;
        this.currY = tmp;
        var res = adversary.run(this);      // g^(a ^ (1 + current + (exponent - (1 + current)))  + ba^current  + ca^(exponent - (1 + current)) + d)
                                            // = g^(a^exponent + ba^current + ca^(exponetn - (1 + current)) + d) 

        this.currX = current.second;
        this.currY = this.g0;
        var t1 = adversary.run(this).multiply(this.gdInverse).invert();

        this.currX = this.g0;
        this.currY = tmp;
        var t2 = adversary.run(this).multiply(this.gdInverse).invert();

        return res.multiply(t1).multiply(t2).multiply(this.gdInverse);
    }
}
