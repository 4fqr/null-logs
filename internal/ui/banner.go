package ui

const Banner = `
███╗   ██╗██╗   ██╗██╗     ██╗         ██╗      ██████╗  ██████╗ 
████╗  ██║██║   ██║██║     ██║         ██║     ██╔═══██╗██╔════╝ 
██╔██╗ ██║██║   ██║██║     ██║         ██║     ██║   ██║██║  ███╗
██║╚██╗██║██║   ██║██║     ██║         ██║     ██║   ██║██║   ██║
██║ ╚████║╚██████╔╝███████╗███████╗    ███████╗╚██████╔╝╚██████╔╝
╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝    ╚══════╝ ╚═════╝  ╚═════╝ 
                                                                   
        Elite Security Observability for Everyone
        From First Hack to First Blue-Team Job
`

// ShowBanner displays the application banner
func ShowBanner() {
	println(Banner)
}
