package lightkeeper.model.instruction;

import java.util.EventListener;

public interface LightKeeperCoverageInstructionModelListener extends EventListener{
    public void instructionsChanged();
}