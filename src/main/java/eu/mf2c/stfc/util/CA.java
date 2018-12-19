/**
 Copyright 2018-20 UKRI Science and Technology Facilities Council

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License 
 */
package eu.mf2c.stfc.util;

/**
 * An enumeration of the supported certification authorities.
 * <p>
 * author Shirley Crompton
 * email  shirley.crompton@stfc.ac.uk
 * org Data Science and Technology Group,
 *      UKRI Science and Technology Council
 * Created 13 Dec 2018
 */
public enum CA {
	IT2TRUSTEDCA,
	IT2UNTRUSTEDCA,
	UC1TRUSTEDCA,
	UC1UNTRUSTEDCA,
	UC2TRUSTEDCA,
	UC2UNTRUSTEDCA,
	UC3TRUSTEDCA,
	UC3UNTRUSTEDCA
}
