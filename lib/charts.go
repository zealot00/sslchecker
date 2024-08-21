package lib

import "fmt"

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	White  = "\033[37m"

	IsEnabledOrSupported     = "[+]"
	IsDisabledOrNotSupported = "[-]"
)

type CommandLineOutput struct {
}

func (cmd *CommandLineOutput) FormatString(info string) string {
	return ""
}
func (cmd *CommandLineOutput) IsEnabledOrSupportStr(str string) {
	fmt.Printf(Green + IsEnabledOrSupported + Reset + " " + str + " is supported or enabled \n")
}
func (cmd *CommandLineOutput) IsDiskabledOrNotSupportStr(str string) string {
	return fmt.Sprintf(White + IsDisabledOrNotSupported + Reset + " " + str + " is not supported or disabled \n")
}
