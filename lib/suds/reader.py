# This program is free software; you can redistribute it and/or modify
# it under the terms of the (LGPL) GNU Lesser General Public License as
# published by the Free Software Foundation; either version 3 of the 
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Library Lesser General Public License for more details at
# ( http://www.gnu.org/licenses/lgpl.html ).
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
# written by: Jeff Ortel ( jortel@redhat.com )

"""
Contains xml document reader classes.
"""


from suds.sax.parser import Parser
from suds.transport import Request

class DocumentReader:
    """
    The XML document reader provides an integration
    between the SAX L{Parser} and the document cache.
    """
    
    def __init__(self, options):
        """
        @param options: An options object.
        @type options: I{Options}
        """
        self.options = options
    
    def open(self, url):
        """
        Open an XML document at the specified I{url}.
        First, the document attempted to be retrieved from
        the I{document cache}.  If not found, it is downloaded and
        parsed using the SAX parser.  The result is added to the
        document store for the next open().
        @param url: A document url.
        @type url: str.
        @return: The specified XML document.
        @rtype: I{Document}
        """
        d = self.options.cache.get(url)
        if d is None:
            fp = self.options.transport.open(Request(url))
            sax = Parser()
            d = sax.parse(file=fp)
            #self.options.cache.put(url, d)
        return d
