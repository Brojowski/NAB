# ----------------------------------------------------------------------
# Copyright (C) 2014, Numenta, Inc.  Unless you have an agreement
# with Numenta, Inc., for a separate license for this software code, the
# following terms and conditions apply:
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero Public License version 3 as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero Public License for more details.
#
# You should have received a copy of the GNU Affero Public License
# along with this program.  If not, see http://www.gnu.org/licenses.
#
# http://numenta.org/licenses/
# ----------------------------------------------------------------------

print("start load")

from numenta_detector import NumentaDetector
import math
from nab.detectors.base import AnomalyDetector

WINDOW_SIZE = 10



class KentDetector(AnomalyDetector):
  """
  This detector uses an HTM based anomaly detection technique.
  """

  def __init__(self, *args, **kwargs):

    super(KentDetector, self).__init__(*args, **kwargs)
    self.windowSize = 0
    self.window = []
    self.rollingSum = 0
    self.rawDetector = NumentaDetector(*args, **kwargs)
    self.windowDetector = NumentaDetector(*args, **kwargs)


  def getAdditionalHeaders(self):
    """Returns a list of strings."""
    return ["windowed_anomaly"]


  def handleRecord(self, inputData):
    """Returns a tuple (numenta_score, windowed_score).

    Internally to NuPIC "anomalyScore" corresponds to "likelihood_score"
    and "rawScore" corresponds to "anomaly_score". Sorry about that.
    """

    value = inputData['value']

    if len(self.window) >= WINDOW_SIZE:
      oldest = self.window.pop(0)
      self.windowSize -= 1
      self.rollingSum -= oldest

    self.window.append(value)
    self.windowSize += 1
    self.rollingSum += value

    # Average of window
    avg = self.rollingSum / self.windowSize

    # Pass inputData to raw detector
    raw = self.rawDetector.handleRecord(inputData)[0]

    avgEntry = dict()
    avgEntry['timestamp'] = inputData['timestamp']
    avgEntry['value'] = avg

    # Pass avg to window detector
    window = self.windowDetector.handleRecord(avgEntry)[0]

    return (raw, window)


  def initialize(self):
    self.rawDetector.initialize()
    self.windowDetector.initialize()

