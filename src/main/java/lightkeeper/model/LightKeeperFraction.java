package lightkeeper.model;

public class LightKeeperFraction implements Comparable<LightKeeperFraction> {
	protected long numerator;
	protected long denominator;
	
	public LightKeeperFraction(long numerator, long denominator) {
		this.numerator = numerator;
		this.denominator = denominator;
	}
	
	public double toPercentage() {
		if (this.denominator == 0)
			return 0;
		return (double)(this.numerator * 100) / this.denominator;
	}
	
	@Override
	public String toString() {
		return String.format("%d / %d", this.numerator, this.denominator);
	}
	
	@Override
	public int compareTo(LightKeeperFraction other) {		
		return Double.compare(this.toPercentage(), other.toPercentage());
	}
}
