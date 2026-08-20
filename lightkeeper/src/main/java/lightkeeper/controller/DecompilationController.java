package lightkeeper.controller;

import java.awt.Color;
import java.util.HashSet;
import java.util.Set;

import generic.theme.GColor;
import ghidra.app.decompiler.CTokenHighlightMatcher;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompilerHighlightService;
import ghidra.app.decompiler.DecompilerHighlighter;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import lightkeeper.LightKeeperPlugin;
import lightkeeper.model.ICoverageModelListener;
import lightkeeper.model.instruction.CoverageInstructionModel;

/**
 * Highlights covered code in the decompiler.
 *
 * The decompiler does not display the background colours which the
 * ColorizingService applies to the listing, so it needs a highlighter of its
 * own. Once created, the decompiler re-applies that highlighter each time a
 * function is decompiled, so it only needs to be refreshed here when the
 * coverage data itself changes.
 */
public class DecompilationController implements ICoverageModelListener {
	protected static final String HIGHLIGHTER_ID = "lightkeeper.coverage";

	protected LightKeeperPlugin plugin;
	protected CoverageInstructionModel model;
	protected GColor color;
	protected DecompilerHighlighter highlighter;

	public DecompilationController(LightKeeperPlugin plugin, CoverageInstructionModel model) {
		this.plugin = plugin;
		this.model = model;
		this.color = new GColor("color.lightkeeper.decompiler_highlight");
	}

	@Override
	public void modelChanged(TaskMonitor monitor) throws CancelledException {
		monitor.checkCancelled();
		Swing.runLater(this::refresh);
	}

	/**
	 * Highlights are applied to the decompiler window, so this must run on the Swing
	 * thread.
	 */
	protected void refresh() {
		var service = plugin.getTool().getService(DecompilerHighlightService.class);
		if (service == null) {
			return;
		}

		if (highlighter == null) {
			highlighter = service.createHighlighter(HIGHLIGHTER_ID, new CoverageTokenMatcher());
		}

		highlighter.clearHighlights();
		highlighter.applyHighlights();
	}

	public void dispose() {
		if (highlighter == null) {
			return;
		}

		highlighter.dispose();
		highlighter = null;
	}

	/**
	 * Matches every token on a line which contains at least one covered
	 * instruction. A single line of decompiled code covers a number of
	 * instructions, so highlighting whole lines gives a closer approximation of the
	 * listing than highlighting only those tokens which map directly onto a covered
	 * address.
	 */
	protected class CoverageTokenMatcher implements CTokenHighlightMatcher {
		protected Set<ClangToken> coveredTokens = new HashSet<>();

		@Override
		public void start(ClangNode root) {
			coveredTokens = new HashSet<>();
			if (root == null) {
				return;
			}

			var ranges = model.getModelData();
			if (ranges.isEmpty()) {
				return;
			}

			for (ClangToken token : DecompilerUtils.getTokens(root, ranges)) {
				var line = token.getLineParent();
				if (line == null) {
					coveredTokens.add(token);
				} else {
					coveredTokens.addAll(line.getAllTokens());
				}
			}
		}

		@Override
		public void end() {
			coveredTokens = new HashSet<>();
		}

		@Override
		public Color getTokenHighlight(ClangToken token) {
			return coveredTokens.contains(token) ? color : null;
		}
	}
}
