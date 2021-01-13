package lightkeeper.model.table;

public class CoveragePercentage extends CoverageFraction{
	public CoveragePercentage(CoverageFraction fraction) {
		super(fraction.numerator, fraction.denominator);
	}

	@Override
	public String toString() {
		var percentage = getDouble() * 100;
		return String.format("%.2f", percentage);
	}
}
