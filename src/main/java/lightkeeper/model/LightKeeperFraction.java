package lightkeeper.model;

public class LightKeeperFraction implements Comparable<LightKeeperFraction> {
	protected long numerator;
	protected long denominator;
	
	public LightKeeperFraction(long numerator, long denominator) {
		this.numerator = numerator;
		this.denominator = denominator;
	}
	
	@Override
	public String toString() {
		return String.format("%d / %d", this.numerator, this.denominator);
	}
	
	@Override
	public int compareTo(LightKeeperFraction other) {
		double thisValue = (double)this.numerator / this.denominator;
		double otherValue = (double)other.numerator / other.denominator;
		return Double.compare(thisValue, otherValue);
	}
}
