PLUGIN_NAME=		suricata2cuckoo
PLUGIN_VERSION=	0.1
PLUGIN_REVISION=	0
PLUGIN_COMMENT=	Suricata file-extraction to Cuckoo Sandbox integration
PLUGIN_MAINTAINER=	kolixxx@users.noreply.github.com

# Perl runtime dependencies for suricata2cuckoo.pl
PLUGIN_DEPENDS=		p5-libwww \
			p5-HTTP-Message \
			p5-XML-XPath \
			p5-File-LibMagic

.include "../../Mk/plugins.mk"

