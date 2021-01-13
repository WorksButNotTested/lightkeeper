package lightkeeper.model.table;

public class LightKeeperPercentage extends LightKeeperFraction{
	public LightKeeperPercentage(LightKeeperFraction fraction) {
		super(fraction.numerator, fraction.denominator);
	}
	
	@Override
	public String toString() {
		double percentage = this.getDouble() * 100;
		return String.format("%.2f", percentage);
	}
}
