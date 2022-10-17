package cdh_quadratic;

import java.math.BigInteger;
import java.util.Random;

import cdh.CDH_Challenge;
import cdh.I_CDH_Challenger;
import genericGroups.IGroupElement;
import utils.NumberUtils;
import utils.Pair;
import utils.StringUtils;
import utils.Triple;

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

    private IGroupElement tempX;
    private IGroupElement tempY;

    private IGroupElement g0; // g^0
    private IGroupElement gd; // g^d
    private IGroupElement gdInverse;    // g^(-d)

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
        this.g0 = this.g.power(BigInteger.ONE);
        this.x = challenge.x;
        this.y = challenge.y;
        this.p = challenge.generator.getGroupOrder();


        // your reduction does not need to be tight. I.e., you may call
        // adversary.run(this) multiple times.

        var gaxy = f4();    // g^(axy)
        

        // Remember that this is a group of prime order p.
        // In particular, we have a^(p-1) = 1 mod p for each a != 0.

        // You can use all classes and methods from the util package:
        var randomNumber = NumberUtils.getRandomBigInteger(new Random(), challenge.generator.getGroupOrder());
        var randomString = StringUtils.generateRandomString(new Random(), 10);
        var pair = new Pair<Integer, Integer>(5, 8);
        var triple = new Triple<Integer, Integer, Integer>(13, 21, 34);

        return null;
    }

    @Override
    public CDH_Challenge<IGroupElement> getChallenge() {

        // This is the second method you need to implement.
        // You need to create a CDH challenge here which will be given to your CDH
        // adversary.
        IGroupElement generator = this.g;
        IGroupElement x = this.tempX;
        IGroupElement y = this.tempY;
        //System.out.println("g: " + g + "\tx: " + x + "\ty: " + y);
        
        // Instead of null, your cdh challenge should consist of meaningful group
        // elements.
        CDH_Challenge<IGroupElement> cdh_challenge = new CDH_Challenge<IGroupElement>(generator, x, y);

        return cdh_challenge;
    }

    private IGroupElement f1() {
        // return g^(axy + bx + cy + d)
        this.tempX = this.x;
        this.tempY = this.y;
        return adversary.run(this);
    }

    private IGroupElement f2() {
        // return f^(axy + bx + cy) = f1 / g^d
        var f1 = f1();

        this.tempX = this.g0;
        this.tempY = this.g0;
        this.gd = adversary.run(this);
        this.gdInverse = this.gd.invert();
        return f1.multiply(this.gdInverse);
    }

    private IGroupElement f3() {
        // return f^(axy + bx) = f2 / g^cy
        var f2 = f2();

        this.tempX = this.g0;
        this.tempY = this.y;
        var gcyd = adversary.run(this);     // g^(cy + d)
        var gcy = gcyd.multiply(this.gdInverse);      // g^(cy)
        return f2.multiply(gcy.invert());
    }

    private IGroupElement f4() {
        // return g^(axy)
        var f3 = f3();
        this.tempX = this.x;
        this.tempY = this.g0;
        var gbxd = adversary.run(this);     // g^(bx + d)
        var gbx = gbxd.multiply(this.gdInverse);      // g^(bx)
        return f3.multiply(gbx);
    }
}
