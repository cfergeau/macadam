TOOLS_BINDIR = $(realpath $(TOOLS_DIR)/bin)

$(TOOLS_BINDIR)/golangci-lint: $(TOOLS_DIR)/go.mod | $(TOOLS_BINDIR)
	cd $(TOOLS_DIR) && GOBIN="$(TOOLS_BINDIR)" go install github.com/golangci/golangci-lint/cmd/golangci-lint

$(TOOLS_BINDIR)/makefat: $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR) && GOBIN="$(TOOLS_BINDIR)" go install github.com/randall77/makefat
