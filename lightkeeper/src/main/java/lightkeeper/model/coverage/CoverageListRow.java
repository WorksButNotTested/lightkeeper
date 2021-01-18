package lightkeeper.model.coverage;

import lightkeeper.io.file.DynamoRioFile;

public class CoverageListRow {
	protected CoverageListState state;
	protected DynamoRioFile file;

	public CoverageListRow(CoverageListState state, DynamoRioFile file) {
		this.state = state;
		this.file = file;
	}

	public CoverageListState getState() {
		return this.state;
	}

	public String getName() {
		return file.getName();
	}

	public DynamoRioFile getFile() {
		return file;
	}

	public void toggle() {
		switch (this.state) {
		case ADDED:
			this.state = CoverageListState.SUBTRACTED;
			break;
		case SUBTRACTED:
			this.state = CoverageListState.IGNORED;
			break;
		case IGNORED:
		default:
			this.state = CoverageListState.ADDED;
			break;
		}
	}

	public void setState(CoverageListState newState) {
		state = newState;
	}
}
