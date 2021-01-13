/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package lightkeeper;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import lightkeeper.controller.Controller;
import lightkeeper.controller.DisassemblyController;
import lightkeeper.model.coverage.CoverageModel;
import lightkeeper.model.instruction.CoverageInstructionModel;
import lightkeeper.model.table.CoverageTableModel;
import lightkeeper.view.LightKeeperProvider;

//@formatter:off
@PluginInfo(
		status = PluginStatus.STABLE,
		packageName = "light keeper",
		category = PluginCategoryNames.MISC,
		shortDescription = "Plugin for visualization of DynamoRio coverage data.",
		description = "Plugin for visualization of DynamoRio coverage data."
		)
//@formatter:on
public class LightKeeperPlugin extends ProgramPlugin {
	protected CoverageModel coverageModel;
	protected CoverageTableModel tableModel;
	protected CoverageInstructionModel instructionModel;
	protected Controller controller;
	protected DisassemblyController disassemblyController;
	protected LightKeeperProvider provider;
	protected Program program;
	protected FlatProgramAPI api;

	public LightKeeperPlugin(PluginTool tool) {
		super(tool, true, true);
		coverageModel = new CoverageModel(this);
		tableModel = new CoverageTableModel(this, coverageModel);
		instructionModel = new CoverageInstructionModel(this, coverageModel);
		coverageModel.addModelListener(tableModel);
		coverageModel.addModelListener(instructionModel);
		controller = new Controller(this, coverageModel, tableModel, instructionModel);
		tableModel.addListener(controller);
		instructionModel.addListener(controller);
		instructionModel.addModelListener(controller);
		disassemblyController = new DisassemblyController(this, instructionModel);
		provider = new LightKeeperProvider(this, controller,  tableModel, "Light Keeper");
	}

	@Override
	public void init() {
		super.init();
	}

	@Override
	public void programActivated(Program activatedProgram) {
		program = activatedProgram;
		api = new FlatProgramAPI(activatedProgram);
	}

	public FlatProgramAPI getApi() {
		return api;
	}
}
