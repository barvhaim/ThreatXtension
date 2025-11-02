"""Module for fetching and extracting Chrome extension metadata from the Chrome Web Store."""

import logging
import re
from typing import Optional, Dict
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class ExtensionMetadata:
    """Fetches metadata for Chrome extensions from the Chrome Web Store"""

    def __init__(self, extension_url: str):
        self.extension_url = extension_url
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/131.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
            }
        )

    def _fetch_page(self):
        """Fetches the HTML content of the extension page"""
        try:
            response = self.session.get(self.extension_url, timeout=10)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error("Error fetching extension page: %s", e)
            return None

    @staticmethod
    def _extract_title(soup: BeautifulSoup) -> Optional[str]:
        """
        Extracts the title of the extension from the page

        HTML: <h1 class="">Shazam: Find song names from your browser</h1>

        Returns:
            str: Title of the extension or None if not found
        """
        try:
            title_tag = soup.find("h1")
            if title_tag:
                title = title_tag.get_text(strip=True)
                logger.debug("Found title: %s", title)
                return title
        except Exception as e:
            logger.error("Error extracting title: %s", e)
        return None

    @staticmethod
    def _extract_user_count(soup: BeautifulSoup) -> Optional[int]:
        """
          Extract user/install count from actual HTML structure

        HTML: <span>9,000,000+ users</span>

        Returns:
            int: User count (0 if not found)

        """
        try:
            text_content = soup.get_text()
            match = re.search(r"([\d,]+)\+?\s*users?", text_content, re.IGNORECASE)
            if match:
                count_str = match.group(1).replace(",", "")
                logger.debug("Found user count via regex: %s", count_str)
                return int(count_str)
        except Exception as e:
            logger.error("Error extracting user count: %s", e)
        return None

    @staticmethod
    def _extract_rating(soup: BeautifulSoup) -> Optional[float]:
        """
        Extract average rating from star display

        HTML: <div role="img" class="" aria-label="4.7 out of 5 stars"
              title="4.7 out of 5 stars"></div>

        Returns:
            float: Rating (0.0 if not found)
        """
        try:
            rating_div = soup.find("div", {"role": "img"})
            if rating_div and "aria-label" in rating_div.attrs:
                aria_label = rating_div["aria-label"]
                match = re.search(r"([\d.]+)\s+out of 5 stars", aria_label)
                if match:
                    rating_str = match.group(1)
                    logger.debug("Found rating via aria-label: %s", rating_str)
                    return float(rating_str)
        except Exception as e:
            logger.error("Error extracting rating: %s", e)
        return None

    @staticmethod
    def extract_ratings_count(soup: BeautifulSoup) -> Optional[int]:
        """
        Extract total ratings count from the extension page

        HTML: <span class="">4 ratings</span>
              <span class="">5K ratings</span>
              <span class="">27.3K ratings</span>

        Returns:
            int: Total ratings count
        """
        try:
            text_content = soup.get_text()
            match = re.search(r"([\d.,]+)([KM]?)\s*ratings?", text_content, re.IGNORECASE)
            if match:
                count_str = match.group(1).replace(",", "")
                multiplier = match.group(2).upper()
                count = float(count_str)
                if multiplier == "K":
                    count *= 1_000
                elif multiplier == "M":
                    count *= 1_000_000
                logger.debug("Found ratings count via regex: %s", int(count))
                return int(count)
        except Exception as e:
            logger.error("Error extracting ratings count: %s", e)
        return None

    @staticmethod
    def _extract_last_updated(soup: BeautifulSoup) -> Optional[str]:
        """
        Extract last updated date using semantic pattern:
        Look for "Updated" text followed by date

        HTML: <li class=""><div class="">Updated</div><div>5 March 2025</div></li>

        Returns:
            str: Last updated date as a string or None if not found
        """
        try:
            for elem in soup.find_all(["div", "span", "td"]):
                # Use the visible text of the element and match against the label
                label_text = elem.get_text(strip=True)
                if re.match(r"^\s*Updated\s*$", label_text, re.IGNORECASE):
                    next_sibling = elem.find_next_sibling()
                    if next_sibling:
                        last_updated = next_sibling.get_text(strip=True)
                        if last_updated:
                            logger.debug("Found last updated date (element): %s", last_updated)
                            return last_updated
        except Exception as e:
            logger.debug("Error extracting last updated date: %s", e)
        return None

    @staticmethod
    def _extract_version(soup: BeautifulSoup) -> Optional[str]:
        """
        Extract version from the extension page

        HTML: <li class="">
                  <div class="">Version</div>
                  <div class="">2.5.0</div>
              </li>

        Returns:
            str: Version as a string or None if not found
        """
        # pylint: disable=too-many-nested-blocks
        try:
            text_content = soup.get_text()
            # Method 1: Find "Version" label and get next element
            for elem in soup.find_all(string=re.compile(r"^\s*Version\s*:?\s*$", re.IGNORECASE)):
                parent = elem.parent
                if parent:
                    # Look at siblings
                    for sibling in parent.next_siblings:
                        if sibling and hasattr(sibling, "text"):
                            text = sibling.text.strip()
                            # Check if it looks like a version number
                            if re.match(r"^\d+\.\d+", text):
                                logger.debug("Found version (sibling): %s", text)
                                return text

                    # Look at parent's next sibling
                    next_elem = parent.find_next_sibling()
                    if next_elem:
                        text = next_elem.text.strip()
                        if re.match(r"^\d+\.\d+", text):
                            logger.debug("Found version (parent sibling): %s", text)
                            return text

            # Method 2: Regex on full text
            match = re.search(
                r"Version[:\s\n]+(\d+\.\d+(?:\.\d+)?(?:\d+)?)", text_content, re.IGNORECASE
            )
            if match:
                version = match.group(1)
                logger.debug("Found version (regex): %s", version)
                return version

        except Exception as e:
            logger.debug("Error extracting version: %s", e)

        return None

    @staticmethod
    def _extract_size(soup) -> Optional[str]:
        """
        Extract size using semantic pattern:
        Look for "Size" label followed by size value

        Pattern: "Size\n528KiB" or "Size: 528KiB"
        """
        try:
            text_content = soup.get_text()
            # Method 1: Find "Size" label
            for elem in soup.find_all(string=re.compile(r"^\s*Size\s*:?\s*$", re.IGNORECASE)):
                parent = elem.parent
                if parent:
                    # Look at next sibling
                    next_elem = parent.find_next_sibling()
                    if next_elem:
                        text = next_elem.text.strip()
                        # Check if it looks like a size (has KiB, MiB, MB, etc.)
                        if re.search(r"\d+\.?\d*\s*(KiB|MiB|KB|MB|GB)", text, re.IGNORECASE):
                            logger.debug("Found size (element): %s", text)
                            return text

            # Method 2: Regex on full text
            match = re.search(
                r"Size[:\s\n]+([\d.]+\s*(?:KiB|MiB|KB|MB|GB))", text_content, re.IGNORECASE
            )
            if match:
                size = match.group(1)
                logger.debug("Found size (regex): %s", size)
                return size

        except Exception as e:
            logger.debug("Error extracting size: %s", e)

        return None

    @staticmethod
    def _extract_developer_name(soup):
        """
        Extract developer name

        Look for:
        1. Near "Developer" or "Offered by" label
        2. Near physical address patterns

        Returns:
            str: Developer name or None
        """
        # pylint: disable=too-many-nested-blocks
        try:
            # Method 1: "Offered by" label
            for elem in soup.find_all(string=re.compile(r"^\s*Offered by\s*:?\s*$", re.IGNORECASE)):
                parent = elem.parent
                if parent:
                    # Get next element
                    for next_elem in parent.find_all_next(limit=10):
                        if next_elem and next_elem.string:
                            text = next_elem.get_text(strip=True)
                            # Developer name is usually one line, not too long
                            if text and 2 < len(text) < 100:
                                name = text.split("\n")[0].strip()
                                logger.debug("Found developer name: %s", name)
                                return name
            # Method 2: "Developer" label
            for elem in soup.find_all(string=re.compile(r"^\s*Developer\s*:?\s*$", re.IGNORECASE)):
                parent = elem.parent
                if parent:
                    next_elem = parent.find_next_sibling()
                    if next_elem:
                        text = next_elem.get_text(strip=True)
                        if text and 2 < len(text) < 100:
                            name = text.split("\n")[0].strip()
                            logger.debug("Found developer name: %s", name)
                            return name
        except Exception as e:
            logger.debug("Error extracting developer name: %s", e)

        return None

    @staticmethod
    def _extract_developer_email(soup) -> Optional[str]:
        """
        Extract developer email from the extension page

        HTML Structure:
        <details class="...">
            <summary>... Email ...</summary>
            <div class="...">qaro.lynnie@gmail.com</div>
        </details>

        Returns:
            str: Developer email or None if not found
        """
        # pylint: disable=too-many-nested-blocks,too-many-branches
        try:
            # Method 1: Look for email inside <details> element
            for details in soup.find_all("details"):
                # Check if summary contains "Email"
                summary = details.find("summary")
                if summary and "email" in summary.get_text(strip=True).lower():
                    # Get the div after summary (contains actual email)
                    email_div = summary.find_next_sibling("div")
                    if email_div:
                        email = email_div.get_text(strip=True)
                        if "@" in email and "." in email:
                            logger.debug("Found email (details): %s", email)
                            return email

            # Method 2: Look for any div that might contain email after "Email" label
            for elem in soup.find_all(string=re.compile(r"Email", re.IGNORECASE)):
                parent = elem.parent
                if parent:
                    # Search in siblings and nearby elements
                    for next_elem in parent.find_all_next(limit=5):
                        text = next_elem.get_text(strip=True)
                        # Check if it looks like an email
                        if "@" in text and "." in text:
                            # Extract email with regex to be safe
                            match = re.search(
                                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", text
                            )
                            if match:
                                email = match.group(0)
                                logger.debug("Found email (near label): %s", email)
                                return email

            # Method 3: mailto: links (fallback)
            for link in soup.find_all("a", href=True):
                href = link["href"]
                if href.startswith("mailto:"):
                    email = href.replace("mailto:", "").strip()
                    if "@" in email and "." in email:
                        logger.debug("Found email (mailto): %s", email)
                        return email

            # Method 4: Email pattern anywhere on page (last resort)
            page_text = soup.get_text()
            match = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", page_text)
            if match:
                email = match.group(0)
                # Filter out obvious non-dev emails
                skip_emails = ["example", "test", "noreply", "support@google", "support@chrome"]
                if not any(skip in email.lower() for skip in skip_emails):
                    logger.debug("Found email (text): %s", email)
                    return email

        except Exception as e:
            logger.debug("Error extracting developer email: %s", e)

        return None

    @staticmethod
    def _extract_website(soup) -> Optional[str]:
        """
        Extract developer website from the extension page

        HTML Structure:
        <a href="https://www.shazam.com/" target="_blank" class="...">
            <svg>...</svg> Website
        </a>

        Returns:
            str: Developer website URL or None if not found
        """
        try:
            # Method 1: Find link with "Website" text
            for link in soup.find_all("a", href=True):
                text = link.get_text(strip=True).lower()
                href = link["href"]

                # Check if link text contains "website"
                if "website" in text and href.startswith("http"):
                    # Skip chrome web store URLs
                    if "chrome.google.com" not in href and "chromewebstore.google.com" not in href:
                        logger.debug("Found website: %s", href)
                        return href

            # Method 2: Look for other website-related keywords
            keywords = ["visit", "homepage", "site", "official site"]
            for link in soup.find_all("a", href=True):
                text = link.get_text(strip=True).lower()
                href = link["href"]

                if any(keyword in text for keyword in keywords) and href.startswith("http"):
                    # Skip chrome web store URLs
                    if "chrome.google.com" not in href and "chromewebstore.google.com" not in href:
                        logger.debug("Found website (keyword): %s", href)
                        return href

            # Method 3: Look for links near "Website" label (if structured differently)
            for elem in soup.find_all(string=re.compile(r"Website", re.IGNORECASE)):
                parent = elem.parent
                if parent and parent.name == "a" and "href" in parent.attrs:
                    href = parent["href"]
                    if href.startswith("http"):
                        logger.debug("Found website (label parent): %s", href)
                        return href

        except Exception as e:
            logger.debug("Error extracting developer website: %s", e)

        return None

    @staticmethod
    def _extract_privacy_policy(soup):
        """
        Extract all text from the Privacy section

        HTML Structure:
        <section>
            <div>
                <h2>Privacy</h2>
            </div>

            <div>
            ...
                <p>...More detailed information can be found in the developer's
                   <a href="https://www.shazam.com/privacy/summary">privacy policy</a>.
                </p>
            </div>
        </section>

        Returns:
            str: All text from Privacy section or None
        """
        try:
            # Find the section with "Privacy" header
            h2 = soup.find("h2", string="Privacy")
            section = h2.parent.parent
            if section:
                privacy_text = section.get_text(separator="\n", strip=True)
                return "\n".join(privacy_text.split("\n")[1:])  # Skip the "Privacy" header line

        except Exception as e:
            logger.debug("Error extracting privacy policy: %s", e)

        return None

    @staticmethod
    def _extract_is_follows_best_practices(soup):
        """
        Check if extension follows Chrome's recommended best practices

        HTML Structure:
        <a jsname=""
           href="https://support.google.com/chrome_webstore/?hl=en-GB&p=cws_badges"
           aria-label="Follows recommended practices for Chrome extensions. Learn more."
           ...>
        </a>

        Returns:
            bool: True if extension follows best practices
        """
        try:
            # Method 1: Look for specific aria-label
            badge_link = soup.find(
                "a",
                attrs={
                    "aria-label": lambda value: value and "recommended practices" in value.lower()
                },
            )

            if badge_link:
                logger.debug("Extension follows recommended practices (aria-label)")
                return True

            # Method 2: Look for URL pattern
            badge_link = soup.find("a", href=lambda href: href and "cws_badges" in href)

            if badge_link:
                logger.debug("Extension follows recommended practices (URL pattern)")
                return True

            # Method 3: Look for text content containing "best practices" or "recommended practices"
            for link in soup.find_all("a"):
                aria_label = link.get("aria-label", "")
                if (
                    "recommended practices" in aria_label.lower()
                    or "best practices" in aria_label.lower()
                ):
                    logger.debug("Extension follows recommended practices (text match)")
                    return True

        except Exception as e:
            logger.debug("Error checking best practices: %s", e)

        return False

    @staticmethod
    def _extract_is_featured(soup) -> bool:
        """
        Check if the extension is featured on the Chrome Web Store

        HTML Structure:
        <span class="">Featured</span>

        Returns:
            bool: True if the extension is featured
        """
        try:
            # Method 1: Look for span with "Featured" text (exact)
            featured_span = soup.find(
                "span", string=lambda _text: _text and _text.strip().lower() == "featured"
            )

            if featured_span:
                logger.debug("Extension is featured (span match)")
                return True

            # Method 2: Look for any element with "Featured" text
            for elem in soup.find_all(["span", "div", "badge"]):
                text = elem.get_text(strip=True)
                if text.lower() == "featured":
                    logger.debug("Extension is featured (text match)")
                    return True

            # Method 3: Search in full page text (fallback)
            page_text = soup.get_text()
            # Look for "Featured" as a standalone badge (not in sentences)
            if re.search(r"\bFeatured\b", page_text):
                logger.debug("Extension is featured (page text)")
                return True

        except Exception as e:
            logger.debug("Error checking featured status: %s", e)

        return False

    @staticmethod
    def _extract_category(soup):
        """
        Returns:
            str: Category path like "Extension > Tools" or None
        """
        try:
            categories = []

            # Find all category links in order
            for link in soup.find_all("a", href=re.compile(r"/category/")):
                category_text = link.get_text(strip=True)
                if category_text and category_text not in categories:
                    categories.append(category_text)

            if categories:
                result = " > ".join(categories)
                logger.debug("Found categories: %s", result)
                return result

        except Exception as e:
            logger.debug("Error extracting category: %s", e)

        return None

    def fetch_metadata(self) -> Optional[Dict]:
        """
        Fetches metadata for the Chrome extension from the Chrome Web Store

        Returns:
            Optional[Dict]: A dictionary containing the extension's metadata,
                or None if fetching fails
        """
        page_content = self._fetch_page()
        if not page_content:
            return None

        soup = BeautifulSoup(page_content, "html.parser")
        metadata = {}

        try:
            metadata["title"] = self._extract_title(soup)

            # Core metrics
            metadata["user_count"] = self._extract_user_count(soup)
            metadata["rating"] = self._extract_rating(soup)
            metadata["ratings_count"] = self.extract_ratings_count(soup)
            metadata["last_updated"] = self._extract_last_updated(soup)
            metadata["version"] = self._extract_version(soup)
            metadata["size"] = self._extract_size(soup)

            # Developer info
            metadata["developer_name"] = self._extract_developer_name(soup)
            metadata["developer_email"] = self._extract_developer_email(soup)
            metadata["developer_website"] = self._extract_website(soup)
            metadata["privacy_policy"] = self._extract_privacy_policy(soup)

            # Additional metadata
            metadata["follows_best_practices"] = self._extract_is_follows_best_practices(soup)
            metadata["is_featured"] = self._extract_is_featured(soup)
            metadata["category"] = self._extract_category(soup)

        except AttributeError as e:
            logger.error("Error parsing extension metadata: %s", e)
            return None

        return metadata
