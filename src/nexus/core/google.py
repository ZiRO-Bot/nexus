"""
Web scrapper for google search
"""


import re
import urllib.parse
from contextlib import suppress
from typing import Any, List, Optional, Union

import aiohttp
import bs4

from nexus.utils.decorators import in_executor


RESULT_STATS_RE = re.compile(r"((?:\d+(?:,)?)+).*(?:\((?:((?:\d+)(?:\.)?(?:\d+)?) (\S+))\))")


class SearchResult:
    def __init__(self, link: str, title: str) -> None:
        self.link: str = link
        self.title: str = title

    def toJson(self) -> dict[str, Any]:
        return {}


class NormalResult(SearchResult):
    def __init__(self, link: str, title: str, content: str) -> None:
        super().__init__(link, title)
        self.content: str = content

    def toJson(self) -> dict[str, Any]:
        return {
            "type": 0,
            "link": self.link,
            "title": self.title,
            "content": self.content,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} link={self.link} title={self.title} contents={self.content}>"

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, NormalResult) and (self.title == other.title and self.content == other.content)


class SpecialResult(SearchResult):
    def __init__(self, title: str, content: Any) -> None:
        super().__init__("https://google.com", title)
        self.content: Any = content

    def toJson(self) -> dict[str, Any]:
        return {
            "type": 1,
            "title": self.title,
            "content": self.content,
        }


class ComplementaryResult(SearchResult):
    def __init__(self, title: str, subtitle: str, description: Union[str, None], info: List[tuple]) -> None:
        super().__init__("https://google.com", title)
        self.subtitle: str = subtitle
        self.description: Union[str, None] = description
        self.info: list[tuple] = info

    def toJson(self) -> dict[str, Any]:
        return {
            "type": 2,
            "title": self.title,
            "subtitle": self.subtitle,
            "description": self.description,
            "info": self.info,
        }

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} title={self.title} subtitle={self.subtitle} description={self.description} info={self.info}>"


class Google:
    def __init__(self) -> None:
        self._fmt: str = "https://www.google.com/search?q={query}&safe={safe}&num={num}&hl={hl}"

    @in_executor()
    def parseResults(self, page: str) -> Optional[dict]:
        soup = bs4.BeautifulSoup(page, "html.parser")
        # eg. "About N results (N seconds)"
        try:
            searchStats = {}
            _searchStats = RESULT_STATS_RE.findall(soup.find(attrs={"id": "result-stats"}).text)[0]  # type: ignore # pyright really don't like bs4
            searchStats["count"] = int(_searchStats[0].replace(",", ""))
            searchStats["duration"] = {"value": float(_searchStats[1]), "unit": _searchStats[2]}
        except (AttributeError, IndexError) as e:
            print(e)
            return {}

        # normal results
        _results = soup.find("div", id="search").find("div", id="rso")
        results = _results.select("div.g[data-hveid], div[data-hveid] > .g")  # type: ignore
        webRes: Optional[List[NormalResult]] = None
        specialRes: Optional[SpecialResult] = None
        # parse both webRes and specialRes (if there is)
        if results:
            webRes = []
            for result in results:
                actualResult = result.find("div", {"data-hveid": True, "data-ved": True})  # type: ignore
                if not actualResult:
                    actualResult = result
                try:
                    _title = actualResult.find("a", href=True)  # type: ignore
                    link = _title["href"]
                    title = _title.find("h3").text
                except (KeyError, TypeError, AttributeError):
                    continue
                else:
                    summary = actualResult.find("div", {"style": "-webkit-line-clamp:2"})
                    if not summary:
                        summary = actualResult.find("div", {"data-content-feature": "1"})
                    if summary and title and link:
                        res = NormalResult(link, title, summary.text)
                        if res not in webRes:
                            webRes.append(res.toJson())

        try:
            _specialRes = _results.select("div.obcontainer")[0]
            isBlock = False
        except IndexError:
            _specialRes = _results.find("block-component")
            isBlock = True
        if _specialRes and not isBlock:
            # Special result such as Currency converter, Maps, etc
            try:
                type = _specialRes.find("h2").text  # type: ignore

                if type == "Currency converter":
                    _contents = _specialRes.find("div", {"data-exchange-rate": True})  # type: ignore
                    contents = _contents.contents
                    formattedContent = {}

                    # Currency stuff
                    _target = contents[0]
                    formattedContent["from"] = {
                        "currency": _target.find("span", {"data-name": True})["data-name"],
                        "value": _target.span.text,
                    }
                    _dest = contents[1]
                    formattedContent["to"] = {
                        "currency": _dest.find("span", {"data-name": True})["data-name"],
                        "value": _dest.find("span", {"data-value": True})["data-value"],
                    }

                    # Last updated
                    formattedContent["last_updated"] = _contents.find_next_sibling().span.text[:-3]
                    specialRes = SpecialResult(type, formattedContent)

                elif type == "Calculator result":
                    result = _specialRes.find("div", role="presentation")
                    ops = result.parent.find_previous_sibling().find("span").text
                    content = {
                        "operation": ops.strip(),
                        "result": result.span.text.strip(),
                    }
                    specialRes = SpecialResult(type, content)
            except AttributeError:
                # Check if it's a unit converter
                if _specialRes.find("select").find("option", value="Energy"):
                    result = _specialRes.find_all("input")
                    content = {
                        "from": {
                            "unit": result[0].find_next_sibling().find("option", selected=True).text,
                            "value": result[0]["value"],
                        },
                        "to": {
                            "unit": result[1].find_next_sibling().find("option", selected=True).text,
                            "value": result[1]["value"],
                        },
                    }
                    specialRes = SpecialResult("Unit converter", content)

        elif _specialRes and isBlock:
            block = _specialRes.find("div", {"data-attrid": True})
            if not block:
                pass
            elif block["data-attrid"] == "dc:/legacy:location_statistical_region_population":
                content = block.find("div", role="heading").text
                specialRes = SpecialResult(
                    block.find_previous_sibling().find("div", role="heading").text.replace("/", " / "), content
                )

        # Complementary results
        complementaryRes = soup.find("div", {"id": "rhs", "data-hveid": True})
        if complementaryRes:
            title: Optional[str] = None
            subtitle: Optional[str] = None
            desc: Optional[str] = None

            with suppress(AttributeError):
                title = complementaryRes.find("h2", {"data-attrid": "title"}).text  # type: ignore
                subtitle = complementaryRes.find("div", {"data-attrid": "subtitle"}).text  # type: ignore

            with suppress(AttributeError):
                desc = complementaryRes.find("div", {"class": "kno-rdesc"}).span.text  # type: ignore

            infoList = complementaryRes.find_all("div", {"data-attrid": True, "lang": True})  # type: ignore
            formattedInfo = []
            for info in infoList:
                key = info.find("span")  # type: ignore
                if not key:
                    continue
                value = key.find_next_sibling()
                if not value:
                    continue
                infoTitle = key.text
                infoContent = value.text
                if infoTitle and infoContent:
                    formattedInfo.append(f"{infoTitle.rstrip()} {infoContent}")

            # A complementary result always have title and subtitle
            if subtitle and title:
                complementaryRes: Union[ComplementaryResult, None] = ComplementaryResult(
                    title, subtitle, desc, formattedInfo
                )
            else:
                complementaryRes = None

        _json = {
            "stats": searchStats,
            "sites": webRes,
        }
        if complementaryRes is not None:
            _json["complementary"] = complementaryRes.toJson()
        if specialRes is not None:
            _json["special"] = specialRes.toJson()
        return _json

    async def search(
        self,
        query: str,
        /,
        *,
        safeSearch: bool = True,
        numberOfResult: int = 10,
        languageCode: str = "en",
    ):
        safe: str = "active" if safeSearch else "images"

        async with aiohttp.ClientSession() as session:
            async with session.get(  # type: ignore
                self._fmt.format(query=urllib.parse.quote(query), safe=safe, num=numberOfResult, hl=languageCode),
                headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/113.0"},
            ) as resp:
                html = await resp.text()
                return await self.parseResults(html)  # type: ignore # executor makes it awaitable
