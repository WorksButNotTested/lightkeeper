package lightkeeper.model.table;

public class CoverageFraction implements Comparable<CoverageFraction> {
	protected long numerator;
	protected long denominator;

	public CoverageFraction(long numerator, long denominator) {
		this.numerator = numerator;
		this.denominator = denominator;
	}

	public double getDouble() {
		if (denominator == 0) {
			return 0;
		}
		return (double)(numerator) / denominator;
	}

	@Override
	public String toString() {
		return String.format("%d / %d", numerator, denominator);
	}

	@Override
	public int compareTo(CoverageFraction other) {
		return Double.compare(getDouble(), other.getDouble());
	}
}
